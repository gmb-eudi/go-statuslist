package statuslist

import (
	"context"
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// interopListURI is the sub/URI baked into the committed fixtures (see
// testdata/interop/SOURCE.md). It must equal StatusRef.URI or the Checker's
// sub-binding (Token Status List §5) rejects the token.
const interopListURI = "https://status-list-go.test/interop/1"

// interopFetcher is a network-free Fetcher that returns the same fixed token
// bytes for any URI (conventions.md: no network in unit tests). There is exactly
// one issued list under test.
type interopFetcher []byte

func (f interopFetcher) Get(_ context.Context, _ string) ([]byte, error) {
	return f, nil
}

// TestInteropStatusListGoFixtures is the permanent, durable half of the Phase B
// cross-repo conformance net. It runs the two committed real-issuer fixtures
// (testdata/interop/, generated once by github.com/unknovs/status-list-go's
// GenerateJWT/GenerateCWT — see SOURCE.md) through the REAL Checker, resolving
// the issuer key from each token's OWN embedded certificate (x5c for the JWT,
// x5chain for the CWT) the way a wallet reading the header would. The issuer repo
// keeps an ephemeral per-run gate (conformance_gate_test.go); this repo keeps the
// exact bytes and re-verifies them forever, so any future status-list-go
// wire-format regression is caught here. Answer key (SOURCE.md): index 3 revoked,
// index 0 valid, for BOTH the ASL-JWT and ASL-CWT formats — 4 assertions total.
func TestInteropStatusListGoFixtures(t *testing.T) {
	// Pin the verifier clock to a fixed instant inside the fixtures' [iat, exp]
	// window (iat ~mid-2026, exp 2035-01-01 per testdata/interop/SOURCE.md) so this
	// permanent regression net verifies the frozen bytes on their own merits forever,
	// independent of the wall clock. Without this, Check() uses time.Now and the test
	// would start failing with ErrExpired after 2035-01-01 — from then on masking any
	// real future wire-format regression behind an unrelated expiry error.
	fixedClock := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		file string
		cert func(*testing.T, []byte) *x509.Certificate
	}{
		{"jwt", "testdata/interop/status-list-go.asl.jwt", certFromJWTHeader},
		{"cwt", "testdata/interop/status-list-go.asl.cwt", certFromCWTHeader},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatalf("read fixture %s: %v", tc.file, err)
			}

			cert := tc.cert(t, raw)

			// Resolve the issuer key straight from the fixture's own embedded
			// certificate — self-describing, the way an EU wallet resolving x5c/
			// x5chain would see it. Trust-anchor validation is intentionally skipped:
			// hard rule 6 governs production code, not a self-contained test fixture.
			resolve := func(_ context.Context, _ string, _ []byte) (stdcrypto.PublicKey, error) {
				return cert.PublicKey, nil
			}

			checker := NewChecker(interopFetcher(raw), nil, WithClock(func() time.Time { return fixedClock }))

			for _, want := range []struct {
				index  int
				status Status
			}{
				{3, StatusRevoked}, // Set(3, 1): INVALID/revoked (Token Status List §7)
				{0, StatusValid},   // untouched: 0x00 VALID — the known-good index
			} {
				st, _, err := checker.Check(context.Background(), CheckInput{
					Ref: StatusRef{
						Kind:   RefTokenStatusList,
						URI:    interopListURI,
						Index:  want.index,
						Format: FormatAuto, // sniff JWT (compact JWS) vs CWT (CBOR)
					},
					IssuerKeyResolver: resolve,
					Policy:            Policy{FailClosed: true},
				})
				if err != nil {
					t.Fatalf("index %d: Check returned error: %v", want.index, err)
				}
				if st != want.status {
					t.Fatalf("index %d: status = %v, want %v", want.index, st, want.status)
				}
			}
		})
	}
}

// certFromJWTHeader extracts the issuer leaf certificate from a compact-JWS
// header's x5c array (RFC 7515 §4.1.6: standard base64, NOT base64url — only the
// three compact segments are base64url).
func certFromJWTHeader(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()

	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		t.Fatalf("jwt: expected 3 compact-JWS segments, got %d", len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("jwt: base64url-decode header segment: %v", err)
	}

	var hdr struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		t.Fatalf("jwt: unmarshal header JSON: %v", err)
	}
	if len(hdr.X5C) == 0 {
		t.Fatalf("jwt: x5c header missing or empty")
	}

	der, err := base64.StdEncoding.DecodeString(hdr.X5C[0])
	if err != nil {
		t.Fatalf("jwt: base64-decode x5c[0]: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("jwt: parse certificate: %v", err)
	}

	return cert
}

// certFromCWTHeader extracts the issuer leaf certificate from a COSE_Sign1's
// protected-header x5chain (label 33). It unwraps the CBOR tag 18 / 4-element
// array / protected-header bstr the same way status-list-go's own test
// (protectedTyp) does, then reads label 33 — which GenerateCWT emits as the
// array form []interface{}{cert.Raw}, though RFC 9360 also allows a bare byte
// string for a single cert; handle both.
func certFromCWTHeader(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()

	var tag cbor.RawTag
	if err := cbor.Unmarshal(raw, &tag); err != nil {
		t.Fatalf("cwt: decode COSE_Sign1 tag: %v", err)
	}
	if tag.Number != 18 {
		t.Fatalf("cwt: expected COSE_Sign1 tag 18, got %d", tag.Number)
	}

	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(tag.Content, &arr); err != nil {
		t.Fatalf("cwt: decode COSE_Sign1 array: %v", err)
	}
	if len(arr) != 4 {
		t.Fatalf("cwt: COSE_Sign1 must have 4 elements, got %d", len(arr))
	}

	var protectedBytes []byte
	if err := cbor.Unmarshal(arr[0], &protectedBytes); err != nil {
		t.Fatalf("cwt: decode protected header bstr: %v", err)
	}

	var protected map[int64]any
	if err := cbor.Unmarshal(protectedBytes, &protected); err != nil {
		t.Fatalf("cwt: decode protected header map: %v", err)
	}

	der := x5chainLeafDER(t, protected[33])

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cwt: parse certificate: %v", err)
	}

	return cert
}

// x5chainLeafDER returns the end-entity certificate DER from a COSE x5chain
// value (label 33): a bare byte string for a single cert, or an array of byte
// strings whose element 0 is the leaf (RFC 9360).
func x5chainLeafDER(t *testing.T, v any) []byte {
	t.Helper()

	switch x := v.(type) {
	case []byte:
		return x
	case []any:
		if len(x) == 0 {
			t.Fatalf("cwt: x5chain (label 33) array is empty")
		}
		der, ok := x[0].([]byte)
		if !ok {
			t.Fatalf("cwt: x5chain[0] is %T, want []byte", x[0])
		}
		return der
	default:
		t.Fatalf("cwt: x5chain (label 33) is %T, want []byte or []any", v)
		return nil
	}
}
