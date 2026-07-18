package statuslist_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	sl "github.com/gmb-eudi/go-statuslist"
)

// fakeFetcher serves a fixed body (no network) and counts calls.
type fakeFetcher struct {
	body  []byte
	err   error
	calls int
}

func (f *fakeFetcher) Get(_ context.Context, _ string) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.body, nil
}

func checkerFor(body []byte, opts ...sl.Option) (*sl.Checker, *fakeFetcher) {
	f := &fakeFetcher{body: body}
	return sl.NewChecker(f, nil, opts...), f
}

func tokenRef(idx int) sl.StatusRef {
	return sl.StatusRef{Kind: sl.RefTokenStatusList, URI: listURI, Index: idx}
}

// Bit widths 1/2/4/8, index lookup, VALID/INVALID/SUSPENDED mapping.
func TestTokenStatusListBitWidthsJWT(t *testing.T) {
	ti := newTestIssuer(t)
	for _, bits := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("bits=%d", bits), func(t *testing.T) {
			statuses := make([]int, 64)
			statuses[3] = 1 // 0x01 INVALID
			if bits >= 2 {
				statuses[5] = 2 // 0x02 SUSPENDED
			}
			tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: bits, statuses: statuses})
			c, fetch := checkerFor(tok)
			want := map[int]sl.Status{0: sl.StatusValid, 3: sl.StatusRevoked}
			if bits >= 2 {
				want[5] = sl.StatusSuspended
			}
			for idx, exp := range want {
				st, prov, err := c.Check(context.Background(), sl.CheckInput{
					Ref:               tokenRef(idx),
					IssuerKeyResolver: ti.resolver(),
					Policy:            sl.Policy{AllowFailOpen: false},
				})
				if err != nil {
					t.Fatalf("idx %d: %v", idx, err)
				}
				if st != exp {
					t.Errorf("idx %d: got %v want %v", idx, st, exp)
				}
				if prov.Bits != bits || prov.Format != "jwt" || prov.Outcome != sl.OutcomeChecked {
					t.Errorf("idx %d: prov %+v", idx, prov)
				}
			}
			if fetch.calls == 0 {
				t.Error("fetcher never called")
			}
		})
	}
}

// Negatives: index-out-of-range, unknown bit width, decompress bomb,
// signature failure — all typed, all fail-closed by default.
func TestTokenStatusListErrorsJWT(t *testing.T) {
	ti := newTestIssuer(t)

	t.Run("index out of range", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: make([]int, 8)})
		c, _ := checkerFor(tok)
		st, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(9999), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrIndexOutOfRange) {
			t.Fatalf("err = %v, want ErrIndexOutOfRange", err)
		}
		if st != sl.StatusUnknown || prov.Outcome != sl.OutcomeUnavailable {
			t.Errorf("prov %+v status %v", prov, st)
		}
	})

	t.Run("unknown bit width", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 3, lst: deflate([]byte{0xFF})})
		c, _ := checkerFor(tok)
		_, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrUnknownBitWidth) {
			t.Fatalf("err = %v, want ErrUnknownBitWidth", err)
		}
	})

	t.Run("decompress bomb capped", func(t *testing.T) {
		bomb := deflate(make([]byte, 8<<20)) // 8 MiB of zeros ⇒ a few KB compressed
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, lst: bomb})
		c, _ := checkerFor(tok, sl.WithMaxDecompressed(1<<20))
		_, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrDecompressTooBig) {
			t.Fatalf("err = %v, want ErrDecompressTooBig", err)
		}
	})

	t.Run("wrong issuer key fails verification", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: make([]int, 8)})
		other := newTestIssuer(t)
		c, _ := checkerFor(tok)
		_, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), IssuerKeyResolver: other.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrVerify) {
			t.Fatalf("err = %v, want ErrVerify", err)
		}
	})

	t.Run("nil resolver fails closed", func(t *testing.T) {
		tok := ti.jwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: make([]int, 8)})
		c, _ := checkerFor(tok)
		_, _, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrKeyUnresolved) {
			t.Fatalf("err = %v, want ErrKeyUnresolved", err)
		}
	})

	t.Run("fetch failure honors fail-open", func(t *testing.T) {
		c := sl.NewChecker(&fakeFetcher{err: errors.New("boom")}, nil)
		st, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(0), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: true},
		})
		if err != nil {
			t.Fatalf("fail-open err = %v", err)
		}
		if st != sl.StatusUnknown || !prov.FailOpen || prov.Outcome != sl.OutcomeSkippedFailOpen {
			t.Errorf("prov %+v status %v", prov, st)
		}
	})
}
