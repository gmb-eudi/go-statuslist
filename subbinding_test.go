package statuslist_test

import (
	"context"
	"errors"
	"testing"

	sl "github.com/gmb-eudi/go-statuslist"
)

// The token sub must equal StatusRef.URI. A mismatch fails
// (fail-closed) for both JWT and CWT; a match still succeeds.
func TestSubBinding(t *testing.T) {
	ti := newTestIssuer(t)
	statuses := []int{0, 1, 0, 0, 0, 0, 0, 0} // idx 1 = INVALID

	forms := map[string]func(tb testing.TB, o tokenOpts) []byte{
		"jwt": ti.jwt,
		"cwt": ti.cwt,
	}
	for name, build := range forms {
		t.Run(name+"/mismatch fails", func(t *testing.T) {
			tok := build(t, tokenOpts{sub: "https://issuer.example/statuslists/OTHER", iat: 1_700_000_000, bits: 1, statuses: statuses})
			c, _ := checkerFor(tok)
			st, prov, err := c.Check(context.Background(), sl.CheckInput{
				Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
			})
			if !errors.Is(err, sl.ErrSubMismatch) {
				t.Fatalf("err = %v, want ErrSubMismatch", err)
			}
			if st != sl.StatusUnknown || prov.Outcome != sl.OutcomeUnavailable {
				t.Errorf("prov %+v status %v", prov, st)
			}
		})
		t.Run(name+"/match succeeds", func(t *testing.T) {
			tok := build(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: statuses})
			c, _ := checkerFor(tok)
			st, _, err := c.Check(context.Background(), sl.CheckInput{
				Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
			})
			if err != nil || st != sl.StatusRevoked {
				t.Fatalf("st=%v err=%v, want StatusRevoked", st, err)
			}
		})
	}
}

// A mismatch under explicit fail-open is skipped, not errored, but never
// reported as a real status (defense against substitution).
func TestSubBindingFailOpen(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.jwt(t, tokenOpts{sub: "https://issuer.example/OTHER", iat: 1_700_000_000, bits: 1, statuses: []int{0, 1}})
	c, _ := checkerFor(tok)
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: true},
	})
	if err != nil || st != sl.StatusUnknown || !prov.FailOpen {
		t.Fatalf("st=%v prov=%+v err=%v", st, prov, err)
	}
}
