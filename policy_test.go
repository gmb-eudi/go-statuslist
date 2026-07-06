package statuslist_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sl "github.com/gmb-eudi/go-statuslist"
)

var epoch = time.Unix(1_700_000_000, 0)

func fixedClock() sl.Option { return sl.WithClock(func() time.Time { return epoch }) }

// T-04.6: ARF Topic 7 VCR_01 — a credential valid < 24h is exempt; the check
// is skipped without any fetch.
func TestShortLivedSkip(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Unix(), bits: 1, statuses: []int{0, 1}})
	f := &fakeFetcher{body: tok}
	c := sl.NewChecker(f, nil, fixedClock())

	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:                tokenRef(1),
		Policy:             sl.Policy{AllowFailOpen: false},
		CredentialValidity: time.Hour, // < 24h
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if st != sl.StatusSkippedShortLived || prov.Outcome != sl.OutcomeSkippedShortLived {
		t.Errorf("st=%v prov=%+v, want StatusSkippedShortLived / skipped-short-lived", st, prov)
	}
	if f.calls != 0 {
		t.Errorf("fetcher called %d times, want 0 (skip precedes fetch)", f.calls)
	}
}

// A credential valid >= 24h is checked normally.
func TestNotShortLivedIsChecked(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Unix(), bits: 1, statuses: []int{0, 1}})
	c, f := checkerFor(tok, fixedClock())
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(),
		Policy: sl.Policy{AllowFailOpen: false}, CredentialValidity: 48 * time.Hour,
	})
	if err != nil || st != sl.StatusRevoked {
		t.Fatalf("st=%v err=%v, want StatusRevoked", st, err)
	}
	if f.calls != 1 {
		t.Errorf("fetcher calls = %d, want 1", f.calls)
	}
}

// Fail-closed surfaces the typed cause; fail-open records the skip.
func TestFetchFailurePolicyBranches(t *testing.T) {
	ti := newTestIssuer(t)
	t.Run("fail-closed", func(t *testing.T) {
		c := sl.NewChecker(&fakeFetcher{err: errors.New("boom")}, nil, fixedClock())
		_, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrFetch) || prov.Outcome != sl.OutcomeUnavailable {
			t.Fatalf("err=%v prov=%+v", err, prov)
		}
	})
	t.Run("fail-open", func(t *testing.T) {
		c := sl.NewChecker(&fakeFetcher{err: errors.New("boom")}, nil, fixedClock())
		st, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: true},
		})
		if err != nil || st != sl.StatusUnknown || !prov.FailOpen || prov.Outcome != sl.OutcomeSkippedFailOpen {
			t.Fatalf("st=%v prov=%+v err=%v", st, prov, err)
		}
	})
}

// T-04.6: MaxStale grace on the token exp.
func TestMaxStale(t *testing.T) {
	ti := newTestIssuer(t)
	statuses := []int{0, 1}

	t.Run("within grace: accepted, marked stale", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Add(-2 * time.Hour).Unix(),
			exp: epoch.Add(-10 * time.Minute).Unix(), bits: 1, statuses: statuses})
		c, _ := checkerFor(tok, fixedClock())
		st, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(),
			Policy: sl.Policy{AllowFailOpen: false, MaxStale: time.Hour},
		})
		if err != nil || st != sl.StatusRevoked {
			t.Fatalf("st=%v err=%v, want StatusRevoked", st, err)
		}
		if !prov.Stale {
			t.Error("prov.Stale = false, want true within MaxStale grace")
		}
	})

	t.Run("beyond grace: expired", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Add(-4 * time.Hour).Unix(),
			exp: epoch.Add(-2 * time.Hour).Unix(), bits: 1, statuses: statuses})
		c, _ := checkerFor(tok, fixedClock())
		_, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(),
			Policy: sl.Policy{AllowFailOpen: false, MaxStale: time.Hour},
		})
		if !errors.Is(err, sl.ErrExpired) || prov.Outcome != sl.OutcomeUnavailable {
			t.Fatalf("err=%v prov=%+v, want ErrExpired / unavailable", err, prov)
		}
	})

	t.Run("not-yet-expired needs no grace", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Unix(),
			exp: epoch.Add(time.Hour).Unix(), bits: 1, statuses: statuses})
		c, _ := checkerFor(tok, fixedClock())
		st, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if err != nil || st != sl.StatusRevoked || prov.Stale {
			t.Fatalf("st=%v prov=%+v err=%v", st, prov, err)
		}
	})
}
