package statuslist_test

import (
	"context"
	"errors"
	"testing"

	sl "github.com/gmb-eudi/go-statuslist"
)

// [Token Status List §5.1] (JWT) and [Token Status List §5.2] (CWT) both mark `sub` and
// `iat` as REQUIRED claims on a Status List Token; [Token Status List §8.3] step 3.2 makes checking
// for required-claim existence a normative Relying Party validation step. A
// token missing either claim decodes to a Go zero value ("" / 0) that is
// indistinguishable from a legitimately-absent value, so decodeClaims rejects
// it with ErrMalformed rather than silently tolerating it (fail closed).
// Both EU reference verifier libraries (Kotlin @Required/isNotBlank,
// Swift guard-throw) already hard-reject the same condition. The missing-iat
// JWT case is covered by TestIatMissingFailsClosed in freshness_test.go (it
// supersedes the old TestIatAbsentSkipsCheck); the CWT equivalent lives here.

// TestSubMissingFailsClosedJWT: an empty/absent sub (JWT) is rejected at decode
// with ErrMalformed — before the referenced-URI binding check, so the failure
// is "malformed token" not "wrong list".
func TestSubMissingFailsClosedJWT(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.jwt(t, tokenOpts{sub: "", iat: 1_700_000_000, bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok)
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{AllowFailOpen: false},
	})
	if !errors.Is(err, sl.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if st != sl.StatusUnknown || prov.Outcome != sl.OutcomeUnavailable {
		t.Errorf("st=%v prov.Outcome=%v, want StatusUnknown/unavailable", st, prov.Outcome)
	}
}

// TestSubMissingFailsClosedCWT: same as above over CWT (claim key 2).
func TestSubMissingFailsClosedCWT(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.cwt(t, tokenOpts{sub: "", iat: 1_700_000_000, bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok)
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{AllowFailOpen: false},
	})
	if !errors.Is(err, sl.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if st != sl.StatusUnknown || prov.Outcome != sl.OutcomeUnavailable {
		t.Errorf("st=%v prov.Outcome=%v, want StatusUnknown/unavailable", st, prov.Outcome)
	}
}

// TestIatMissingFailsClosedCWT: iat == 0 (the Go zero value for an absent
// claim) is rejected over CWT (claim key 6). The JWT equivalent is
// TestIatMissingFailsClosed in freshness_test.go.
func TestIatMissingFailsClosedCWT(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.cwt(t, tokenOpts{sub: listURI, iat: 0, bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok)
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{AllowFailOpen: false},
	})
	if !errors.Is(err, sl.ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
	if st != sl.StatusUnknown || prov.Outcome != sl.OutcomeUnavailable {
		t.Errorf("st=%v prov.Outcome=%v, want StatusUnknown/unavailable", st, prov.Outcome)
	}
}
