package statuslist_test

import (
	"bytes"
	"compress/zlib"
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
	sl "github.com/gmb-eudi/go-statuslist"
)

const (
	testKeyID = "statuslist-issuer-key-1"
	listURI   = "https://issuer.example/statuslists/1"
)

// testIssuer is a minimal in-test Status List Token issuer built on
// go-eudi-crypto (ADR-0007 permits generated vectors — draft-ietf-oauth-status-list
// is not vendored in references/, see SPECREFS.md). It signs JWT (§5.1) and
// CWT (§5.2) status list tokens (and identifier lists, Task 5) with a fresh
// P-256 key. All builders take testing.TB so both tests and fuzz seeds use them.
type testIssuer struct {
	key *ecdsa.PrivateKey
	kp  eudicrypto.KeyProvider
}

func newTestIssuer(tb testing.TB) *testIssuer {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return &testIssuer{key: k, kp: eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{testKeyID: k})}
}

// resolver yields this issuer's public key for any URI/token. Tests that want a
// signature failure pass a different issuer's resolver.
func (ti *testIssuer) resolver() sl.KeyResolver {
	return func(_ context.Context, _ string, _ []byte) (stdcrypto.PublicKey, error) {
		return ti.key.Public(), nil
	}
}

// packBits packs statuses little-endian per draft-ietf-oauth-status-list §4:
// entry 0 occupies the least-significant bits of byte 0.
func packBits(bits int, statuses []int) []byte {
	perByte := 8 / bits
	out := make([]byte, (len(statuses)+perByte-1)/perByte)
	mask := byte((1 << bits) - 1)
	for i, s := range statuses {
		out[i/perByte] |= (byte(s) & mask) << uint((i%perByte)*bits) //nolint:gosec // G115: s is a test status value 0-3, always fits in a byte
	}
	return out
}

func deflate(b []byte) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

// tokenOpts describes a status list token to build. If lst is non-nil it is
// used verbatim (already deflated) — for crafting bombs / odd bit widths.
type tokenOpts struct {
	sub      string
	iat      int64
	exp      int64 // 0 = omit
	ttl      int64 // 0 = omit
	bits     int
	statuses []int
	lst      []byte
}

func (o tokenOpts) compressed() []byte {
	if o.lst != nil {
		return o.lst
	}
	return deflate(packBits(o.bits, o.statuses))
}

// jwt builds and signs a JWT Status List Token (§5.1). lst is base64url.
func (ti *testIssuer) jwt(tb testing.TB, o tokenOpts) []byte {
	tb.Helper()
	payload := map[string]any{
		"sub": o.sub,
		"iat": o.iat,
		"status_list": map[string]any{
			"bits": o.bits,
			"lst":  base64.RawURLEncoding.EncodeToString(o.compressed()),
		},
	}
	if o.exp != 0 {
		payload["exp"] = o.exp
	}
	if o.ttl != 0 {
		payload["ttl"] = o.ttl
	}
	body, err := json.Marshal(payload)
	if err != nil {
		tb.Fatal(err)
	}
	tok, err := eudicrypto.SignJWS(context.Background(), ti.kp, testKeyID,
		map[string]any{"typ": "statuslist+jwt", "kid": testKeyID}, body)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}

// cwt builds and signs a CWT Status List Token (§5.2). Claim keys sub=2,
// exp=4, iat=6, ttl=65534, status_list=65533; lst is a CBOR byte string.
// (Private claim keys are FLAGGED for verification — see cwt.go / SPECREFS.md.)
func (ti *testIssuer) cwt(tb testing.TB, o tokenOpts) []byte {
	tb.Helper()
	claims := map[int64]any{
		2:     o.sub,
		6:     o.iat,
		65533: map[string]any{"bits": o.bits, "lst": o.compressed()},
	}
	if o.exp != 0 {
		claims[4] = o.exp
	}
	if o.ttl != 0 {
		claims[65534] = o.ttl
	}
	body, err := cbor.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	tok, err := eudicrypto.SignCOSESign1(context.Background(), ti.kp, testKeyID,
		eudicrypto.COSEHeader{16: "application/statuslist+cwt", 4: []byte(testKeyID)}, body)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}

// idListOpts describes an Attestation Revocation List ("Identifier List") token.
type idListOpts struct {
	sub string
	iat int64
	exp int64 // 0 = omit
	ttl int64 // 0 = omit
	ids []string
}

// idJWT builds and signs a JSON identifier-list token (synthetic shape — see
// identifier.go format FLAG).
func (ti *testIssuer) idJWT(tb testing.TB, o idListOpts) []byte {
	tb.Helper()
	payload := map[string]any{
		"sub":             o.sub,
		"iat":             o.iat,
		"identifier_list": map[string]any{"ids": o.ids},
	}
	if o.exp != 0 {
		payload["exp"] = o.exp
	}
	if o.ttl != 0 {
		payload["ttl"] = o.ttl
	}
	body, err := json.Marshal(payload)
	if err != nil {
		tb.Fatal(err)
	}
	tok, err := eudicrypto.SignJWS(context.Background(), ti.kp, testKeyID,
		map[string]any{"typ": "identifierlist+jwt", "kid": testKeyID}, body)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}

// idCWT builds and signs a CBOR identifier-list token (claim key 65532 = FLAG).
func (ti *testIssuer) idCWT(tb testing.TB, o idListOpts) []byte {
	tb.Helper()
	claims := map[int64]any{
		2:     o.sub,
		6:     o.iat,
		65532: map[string]any{"ids": o.ids},
	}
	if o.exp != 0 {
		claims[4] = o.exp
	}
	if o.ttl != 0 {
		claims[65534] = o.ttl
	}
	body, err := cbor.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	tok, err := eudicrypto.SignCOSESign1(context.Background(), ti.kp, testKeyID,
		eudicrypto.COSEHeader{16: "application/identifierlist+cwt", 4: []byte(testKeyID)}, body)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}

// rawJWT signs an arbitrary JSON claims map, bypassing idJWT/jwt's fixed
// shape. Test-only escape hatch for crafting wrong-shape payloads (e.g. a
// token that omits the identifier_list wrapper entirely) to exercise the
// fail-closed guard in decodeIdentifierList.
func (ti *testIssuer) rawJWT(tb testing.TB, claims map[string]any) []byte {
	tb.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	tok, err := eudicrypto.SignJWS(context.Background(), ti.kp, testKeyID,
		map[string]any{"typ": "identifierlist+jwt", "kid": testKeyID}, body)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}

// rawCWT signs an arbitrary CBOR claims map (int64 keys), the CWT analogue of
// rawJWT.
func (ti *testIssuer) rawCWT(tb testing.TB, claims map[int64]any) []byte {
	tb.Helper()
	body, err := cbor.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	tok, err := eudicrypto.SignCOSESign1(context.Background(), ti.kp, testKeyID,
		eudicrypto.COSEHeader{16: "application/identifierlist+cwt", 4: []byte(testKeyID)}, body)
	if err != nil {
		tb.Fatal(err)
	}
	return tok
}
