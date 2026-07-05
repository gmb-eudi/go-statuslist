package statuslist_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sl "github.com/gmb-eudi/go-statuslist"
)

// Task A3: the Status List Token's `iat` must not be in the future (RFC 8392
// iat; draft §5), and a per-checker WithClockSkew tolerates clock differences
// between issuer and verifier on both iat and exp. Policy.MaxStale remains a
// separate, deliberate staleness grace beyond exp; the two compose (fail
// closed, hard rule 7).

// TestIatInFutureNoSkew: with no configured clock skew, a token whose iat is
// after the checker's clock is rejected with ErrIssuedInFuture.
func TestIatInFutureNoSkew(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: fixed.Add(time.Hour).Unix(), bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }))
	_, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if !errors.Is(err, sl.ErrIssuedInFuture) {
		t.Fatalf("err = %v, want ErrIssuedInFuture", err)
	}
}

// TestIatWithinSkewPasses: an iat that is ahead of the clock but within the
// configured ClockSkew tolerance is accepted.
func TestIatWithinSkewPasses(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: fixed.Add(2 * time.Minute).Unix(), bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }), sl.WithClockSkew(5*time.Minute))
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
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

// TestExpWithinSkewStillAccepted: an exp that has just elapsed but is within
// the configured ClockSkew is accepted (even with MaxStale == 0), and the
// result is marked Stale since now is after exp.
func TestExpWithinSkewStillAccepted(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.jwt(t, tokenOpts{
		sub: listURI, iat: fixed.Add(-time.Hour).Unix(),
		exp: fixed.Add(-2 * time.Minute).Unix(), bits: 1, statuses: []int{0},
	})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }), sl.WithClockSkew(5*time.Minute))
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{},
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if st != sl.StatusValid {
		t.Fatalf("st = %v, want StatusValid", st)
	}
	if !prov.Stale {
		t.Error("prov.Stale = false, want true (now is after exp)")
	}
}

// TestIatAbsentSkipsCheck: iat == 0 means "absent" and must not trip
// ErrIssuedInFuture, regardless of clock.
func TestIatAbsentSkipsCheck(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 0, bits: 1, statuses: []int{0}})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }))
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               tokenRef(0),
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

// TestIatInFutureIdentifierList: the iat check applies identically to the
// Identifier List path via tokenMeta/metaFrom.
func TestIatInFutureIdentifierList(t *testing.T) {
	ti := newTestIssuer(t)
	fixed := time.Unix(1_700_000_000, 0)
	tok := ti.idJWT(t, idListOpts{sub: listURI, iat: fixed.Add(time.Hour).Unix(), ids: []string{"5"}})
	c, _ := checkerFor(tok, sl.WithClock(func() time.Time { return fixed }))
	_, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               sl.StatusRef{Kind: sl.RefIdentifierList, URI: listURI, ID: "5"},
		IssuerKeyResolver: ti.resolver(),
		Policy:            sl.Policy{FailClosed: true},
	})
	if !errors.Is(err, sl.ErrIssuedInFuture) {
		t.Fatalf("err = %v, want ErrIssuedInFuture", err)
	}
}
