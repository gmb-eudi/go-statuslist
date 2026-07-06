package statuslist_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	sl "github.com/gmb-eudi/go-statuslist"
)

// Task A2: the Status List Token's `typ` (JOSE header / COSE label 16) is
// REQUIRED and must equal the status-list media type (draft §5.1/§5.2). A
// token of another type must never be accepted for a status-list reference,
// even if its signature and sub bind — fail closed (hard rule 7).

// statusListJWTBody returns a valid status-list JSON claims body (§5.1) bound
// to listURI, independent of the `typ` header under test.
func statusListJWTBody(tb testing.TB) []byte {
	tb.Helper()
	body, err := json.Marshal(map[string]any{
		"sub": listURI,
		"iat": int64(1),
		"status_list": map[string]any{
			"bits": 1,
			"lst":  base64.RawURLEncoding.EncodeToString(deflate(packBits(1, []int{0}))),
		},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return body
}

// statusListCWTBody returns a valid status-list CBOR claims body (§5.2) bound
// to listURI, independent of the `typ` header under test.
func statusListCWTBody(tb testing.TB) []byte {
	tb.Helper()
	claims := map[int64]any{
		2: listURI,
		6: int64(1),
		65533: map[string]any{
			"bits": 1,
			"lst":  deflate(packBits(1, []int{0})),
		},
	}
	body, err := cbor.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	return body
}

func TestTypJWTWrongOrMissing(t *testing.T) {
	ti := newTestIssuer(t)

	t.Run("wrong typ", func(t *testing.T) {
		body := statusListJWTBody(t)
		raw, err := eudicrypto.SignJWS(context.Background(), ti.kp, testKeyID,
			map[string]any{"typ": "JWT", "kid": testKeyID}, body)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := checkerFor(raw)
		_, _, err = c.Check(context.Background(), sl.CheckInput{
			Ref:               tokenRef(0),
			IssuerKeyResolver: ti.resolver(),
			Policy:            sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrWrongType) {
			t.Fatalf("err = %v, want ErrWrongType", err)
		}
	})

	t.Run("missing typ", func(t *testing.T) {
		body := statusListJWTBody(t)
		raw, err := eudicrypto.SignJWS(context.Background(), ti.kp, testKeyID,
			map[string]any{"kid": testKeyID}, body)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := checkerFor(raw)
		_, _, err = c.Check(context.Background(), sl.CheckInput{
			Ref:               tokenRef(0),
			IssuerKeyResolver: ti.resolver(),
			Policy:            sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrWrongType) {
			t.Fatalf("err = %v, want ErrWrongType", err)
		}
	})
}

func TestTypCWTWrongOrMissing(t *testing.T) {
	ti := newTestIssuer(t)

	t.Run("wrong typ", func(t *testing.T) {
		body := statusListCWTBody(t)
		raw, err := eudicrypto.SignCOSESign1(context.Background(), ti.kp, testKeyID,
			eudicrypto.COSEHeader{16: "application/cbor", 4: []byte(testKeyID)}, body)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := checkerFor(raw)
		_, _, err = c.Check(context.Background(), sl.CheckInput{
			Ref:               tokenRef(0),
			IssuerKeyResolver: ti.resolver(),
			Policy:            sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrWrongType) {
			t.Fatalf("err = %v, want ErrWrongType", err)
		}
	})

	t.Run("missing typ", func(t *testing.T) {
		body := statusListCWTBody(t)
		raw, err := eudicrypto.SignCOSESign1(context.Background(), ti.kp, testKeyID,
			eudicrypto.COSEHeader{4: []byte(testKeyID)}, body)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := checkerFor(raw)
		_, _, err = c.Check(context.Background(), sl.CheckInput{
			Ref:               tokenRef(0),
			IssuerKeyResolver: ti.resolver(),
			Policy:            sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrWrongType) {
			t.Fatalf("err = %v, want ErrWrongType", err)
		}
	})
}

// TestTypCorrectPasses is the explicit positive: a correctly-typed status-list
// JWT does not hit ErrWrongType (the wider suite in token_jwt_test.go /
// token_cwt_test.go already relies on this implicitly via ti.jwt/ti.cwt).
func TestTypCorrectPasses(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok)
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{AllowFailOpen: false},
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if st != sl.StatusValid {
		t.Fatalf("st = %v, want StatusValid", st)
	}
}

// TestTypNotValidatedForIdentifierList is the regression guard for the
// verifyToken Ref.Kind gate: the Identifier List (ARL) path shares
// verifyToken with the status-list path but carries a different `typ`
// (identifierlist+jwt). It must keep verifying without tripping
// ErrWrongType — proving typ validation is scoped to RefTokenStatusList only.
func TestTypNotValidatedForIdentifierList(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idJWT(t, idListOpts{sub: listURI, iat: 1_700_000_000, ids: []string{"5"}})
	c, _ := checkerFor(tok)
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               sl.StatusRef{Kind: sl.RefIdentifierList, URI: listURI, ID: "5"},
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{AllowFailOpen: false},
	})
	if errors.Is(err, sl.ErrWrongType) {
		t.Fatalf("err = %v, ARL path must not be typ-validated", err)
	}
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if st != sl.StatusRevoked {
		t.Fatalf("st = %v, want StatusRevoked", st)
	}
}
