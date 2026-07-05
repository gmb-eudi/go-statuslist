package statuslist_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	sl "github.com/gmb-eudi/go-statuslist"
)

// T-04.3: same bit-width / index / status matrix as T-04.2, over CWT (COSE).
func TestTokenStatusListBitWidthsCWT(t *testing.T) {
	ti := newTestIssuer(t)
	for _, bits := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("bits=%d", bits), func(t *testing.T) {
			statuses := make([]int, 64)
			statuses[3] = 1
			if bits >= 2 {
				statuses[5] = 2
			}
			tok := ti.cwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: bits, statuses: statuses})
			c, _ := checkerFor(tok)
			want := map[int]sl.Status{0: sl.StatusValid, 3: sl.StatusRevoked}
			if bits >= 2 {
				want[5] = sl.StatusSuspended
			}
			for idx, exp := range want {
				st, prov, err := c.Check(context.Background(), sl.CheckInput{
					Ref:               tokenRef(idx),
					IssuerKeyResolver: ti.resolver(),
					Policy:            sl.Policy{FailClosed: true},
				})
				if err != nil {
					t.Fatalf("idx %d: %v", idx, err)
				}
				if st != exp {
					t.Errorf("idx %d: got %v want %v", idx, st, exp)
				}
				if prov.Format != "cwt" || prov.Bits != bits || prov.Outcome != sl.OutcomeChecked {
					t.Errorf("idx %d: prov %+v", idx, prov)
				}
			}
		})
	}
}

// T-04.3 negatives over CWT: index OOR, unknown bit width, decompress bomb,
// signature failure — all typed, all fail-closed.
func TestTokenStatusListErrorsCWT(t *testing.T) {
	ti := newTestIssuer(t)
	cases := []struct {
		name string
		tok  []byte
		ref  sl.StatusRef
		opt  []sl.Option
		res  sl.KeyResolver
		want error
	}{
		{"index out of range",
			ti.cwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: make([]int, 8)}),
			tokenRef(9999), nil, ti.resolver(), sl.ErrIndexOutOfRange},
		{"unknown bit width",
			ti.cwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 3, lst: deflate([]byte{0xFF})}),
			tokenRef(0), nil, ti.resolver(), sl.ErrUnknownBitWidth},
		{"decompress bomb",
			ti.cwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, lst: deflate(make([]byte, 8<<20))}),
			tokenRef(0), []sl.Option{sl.WithMaxDecompressed(1 << 20)}, ti.resolver(), sl.ErrDecompressTooBig},
		{"wrong key",
			ti.cwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: make([]int, 8)}),
			tokenRef(0), nil, newTestIssuer(t).resolver(), sl.ErrVerify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := checkerFor(tc.tok, tc.opt...)
			_, _, err := c.Check(context.Background(), sl.CheckInput{
				Ref: tc.ref, IssuerKeyResolver: tc.res, Policy: sl.Policy{FailClosed: true},
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// FormatAuto sniffs CWT (CBOR is not JWS-shaped); an explicit override is honoured.
func TestFormatSniffAndOverride(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.cwt(t, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: []int{0, 1, 0, 0, 0, 0, 0, 0}})
	c, _ := checkerFor(tok)
	// FormatAuto (default zero value) must resolve to CWT and read INVALID at idx 1.
	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               sl.StatusRef{Kind: sl.RefTokenStatusList, URI: listURI, Index: 1, Format: sl.FormatAuto},
		IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{FailClosed: true},
	})
	if err != nil || st != sl.StatusRevoked || prov.Format != "cwt" {
		t.Fatalf("auto-sniff: st=%v prov=%+v err=%v", st, prov, err)
	}
	// Explicit FormatJWT on a CWT body must fail verification (not panic).
	_, _, err = c.Check(context.Background(), sl.CheckInput{
		Ref:               sl.StatusRef{Kind: sl.RefTokenStatusList, URI: listURI, Index: 1, Format: sl.FormatJWT},
		IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{FailClosed: true},
	})
	if err == nil {
		t.Fatal("CWT body verified as JWT unexpectedly succeeded")
	}
}
