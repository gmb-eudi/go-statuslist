package statuslist_test

import (
	"context"
	"testing"

	sl "github.com/gmb-eudi/go-statuslist"
)

// FuzzStatusListToken feeds arbitrary bytes as a status list token through the
// full fetch→verify→decode→inflate→index path. It must never panic (hard rule 5).
func FuzzStatusListToken(f *testing.F) {
	ti := newTestIssuer(f)
	f.Add(ti.jwt(f, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 1, statuses: []int{0, 1, 0, 1, 0, 0, 0, 0}}))
	f.Add(ti.jwt(f, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 8, statuses: []int{0, 1, 2, 3}}))
	f.Add(ti.jwt(f, tokenOpts{sub: "wrong", iat: 1_700_000_000, bits: 1, lst: deflate([]byte{0xFF})}))
	f.Add(ti.cwt(f, tokenOpts{sub: listURI, iat: 1_700_000_000, bits: 2, statuses: []int{0, 1, 2, 3}}))
	f.Add(ti.cwt(f, tokenOpts{sub: "wrong", iat: 1_700_000_000, bits: 4, lst: deflate([]byte{0xAB, 0xCD})}))
	f.Add([]byte(""))
	f.Add([]byte("."))
	f.Add([]byte("a.b.c"))
	f.Add([]byte("aaaa.bbbb.cccc"))
	f.Add([]byte{0x84, 0x40, 0xa0, 0x40, 0x40}) // COSE_Sign1-shaped CBOR array

	f.Fuzz(func(_ *testing.T, tok []byte) {
		c := sl.NewChecker(&fakeFetcher{body: append([]byte(nil), tok...)}, nil, sl.WithMaxDecompressed(1<<16))
		_, _, _ = c.Check(context.Background(), sl.CheckInput{
			Ref:               tokenRef(3),
			IssuerKeyResolver: ti.resolver(),
			Policy:            sl.Policy{FailClosed: true},
		})
	})
}
