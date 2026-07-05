package statuslist_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sl "github.com/gmb-eudi/go-statuslist"
)

func TestNewCheckerNonNil(t *testing.T) {
	if sl.NewChecker(nil, nil) == nil {
		t.Fatal("NewChecker returned nil")
	}
}

// Fail-closed is the default posture; fail-open requires the explicit
// per-client flag (Policy.FailClosed == false) and is recorded in Provenance
// (hard rule 7). Exercised here via an unsupported ref kind so the test stays
// valid for the whole WP (Task 2/5 never make RefKind(99) meaningful).
func TestFailClosedPolicy(t *testing.T) {
	clk := func() time.Time { return time.Unix(1_700_000_000, 0) }
	c := sl.NewChecker(nil, nil, sl.WithClock(clk))
	ref := sl.StatusRef{Kind: sl.RefKind(99), URI: "https://issuer.example/list/1", Index: 4}

	st, prov, err := c.Check(context.Background(), sl.CheckInput{Ref: ref, Policy: sl.Policy{FailClosed: true}})
	if !errors.Is(err, sl.ErrUnsupported) {
		t.Fatalf("fail-closed err = %v, want ErrUnsupported", err)
	}
	if st != sl.StatusUnknown {
		t.Errorf("fail-closed status = %v, want StatusUnknown", st)
	}
	if prov.Outcome != sl.OutcomeUnavailable || prov.FailOpen {
		t.Errorf("fail-closed prov = %+v, want Outcome=unavailable FailOpen=false", prov)
	}

	st, prov, err = c.Check(context.Background(), sl.CheckInput{Ref: ref, Policy: sl.Policy{FailClosed: false}})
	if err != nil {
		t.Fatalf("fail-open err = %v, want nil", err)
	}
	if st != sl.StatusUnknown || prov.Outcome != sl.OutcomeSkippedFailOpen || !prov.FailOpen {
		t.Errorf("fail-open prov = %+v status = %v, want Outcome=skipped-fail-open FailOpen=true StatusUnknown", prov, st)
	}
	if prov.URI != ref.URI || prov.Index != ref.Index {
		t.Errorf("prov did not carry the ref: %+v", prov)
	}
}

// Outcome values are stable, value-free strings embedded verbatim in the
// verification report (hard rule 7).
func TestOutcomeStringsStable(t *testing.T) {
	for got, want := range map[sl.Outcome]string{
		sl.OutcomeChecked:           "checked",
		sl.OutcomeCached:            "checked-cached",
		sl.OutcomeSkippedShortLived: "skipped-short-lived",
		sl.OutcomeSkippedFailOpen:   "skipped-fail-open",
		sl.OutcomeUnavailable:       "unavailable",
	} {
		if string(got) != want {
			t.Errorf("Outcome = %q, want %q", string(got), want)
		}
	}
}

func TestStatusString(t *testing.T) {
	for s, want := range map[sl.Status]string{
		sl.StatusValid:             "valid",
		sl.StatusRevoked:           "revoked",
		sl.StatusSuspended:         "suspended",
		sl.StatusUnknown:           "unknown",
		sl.StatusSkippedShortLived: "skipped-short-lived",
	} {
		if s.String() != want {
			t.Errorf("Status.String() = %q, want %q", s.String(), want)
		}
	}
}
