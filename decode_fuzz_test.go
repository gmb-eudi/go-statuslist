package statuslist

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Final-review fix (T-04.7, hard rule 5): FuzzStatusListToken (fuzz_test.go)
// runs full signature verification before decoding, so a mutated input dies
// at ErrVerify on essentially every run and the claim/identifier-list decoders
// underneath are, in practice, unfuzzed. These white-box targets call the
// unexported decoders directly with fuzzed bytes — mirroring how
// inflate_fuzz_test.go drives (*Checker).inflate directly — so malformed CBOR
// and JSON reach decodeJWTClaims/decodeCWTClaims/decodeIdentifierList without
// first needing a valid signature. Invariant: never panic; a malformed input
// must return an error (ideally wrapping ErrMalformed), never crash.

// FuzzDecodeClaims drives decodeClaims for both wire formats ("jwt" claims via
// decodeJWTClaims, "cwt" claims via decodeCWTClaims) directly with fuzzed
// bytes.
func FuzzDecodeClaims(f *testing.F) {
	// A real JSON claims blob (jwtPayload shape, Token Status List §5.1).
	validJSON, err := json.Marshal(map[string]any{
		"sub": "https://issuer.example/statuslists/1",
		"iat": 1_700_000_000,
		"exp": 1_800_000_000,
		"ttl": 3600,
		"status_list": map[string]any{
			"bits": 1,
			"lst":  base64.RawURLEncoding.EncodeToString([]byte{0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01}),
		},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validJSON)

	// A real CBOR claims blob (cwtPayload shape, Token Status List §5.2).
	validCBOR, err := cbor.Marshal(map[int64]any{
		2:     "https://issuer.example/statuslists/1",
		4:     int64(1_800_000_000),
		6:     int64(1_700_000_000),
		65534: int64(3600),
		65533: map[string]any{"bits": 1, "lst": []byte{0xAA}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validCBOR)

	f.Add([]byte(nil))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("not json or cbor"))
	f.Add([]byte(`{"sub":1,"status_list":{"bits":"nope"}}`)) // wrong JSON types
	f.Add([]byte{0xa1})                                      // truncated CBOR map (header claims 1 pair, none present)
	f.Add([]byte{0xbf, 0x01, 0x02, 0xff})                    // indefinite-length map (forbidden by cwtDecMode)
	f.Add([]byte{0x9f, 0x01, 0x02, 0xff})                    // indefinite-length array (forbidden by cwtDecMode)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = decodeClaims("jwt", data)
		_, _ = decodeClaims("cwt", data)
	})
}

// FuzzDecodeIdentifierList drives decodeIdentifierList for both wire formats
// directly with fuzzed bytes (the ARF Attestation Revocation List / VCR_11
// mechanism, ADR-0007) — this parser previously had zero fuzz coverage.
func FuzzDecodeIdentifierList(f *testing.F) {
	// A real JSON identifier-list blob (jsonIDList shape).
	validJSON, err := json.Marshal(map[string]any{
		"sub":             "https://issuer.example/revlists/1",
		"iat":             1_700_000_000,
		"exp":             1_800_000_000,
		"ttl":             3600,
		"identifier_list": map[string]any{"ids": []string{"urn:cred:aaa", "urn:cred:bbb"}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validJSON)

	// A real CBOR identifier-list blob (cborIDList shape).
	validCBOR, err := cbor.Marshal(map[int64]any{
		2:     "https://issuer.example/revlists/1",
		4:     int64(1_800_000_000),
		6:     int64(1_700_000_000),
		65534: int64(3600),
		65532: map[string]any{"ids": []string{"urn:cred:aaa", "urn:cred:bbb"}},
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validCBOR)

	f.Add([]byte(nil))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("not json or cbor"))
	f.Add([]byte(`{"identifier_list":{"ids":[1,2,3]}}`)) // wrong element type for ids
	f.Add([]byte{0xa1})                                  // truncated CBOR map
	f.Add([]byte{0xbf, 0x01, 0x02, 0xff})                // indefinite-length map (forbidden by cwtDecMode)
	f.Add([]byte{0x9f, 0x01, 0x02, 0xff})                // indefinite-length array (forbidden by cwtDecMode)

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = decodeIdentifierList("jwt", data)
		_, _, _ = decodeIdentifierList("cwt", data)
	})
}
