package statuslist

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/gmb-eudi/go-statuslist/spec"
)

func TestSpecClaimKeysMatchWireTags(t *testing.T) {
	// Build a CWT claims map keyed by the spec constants, then decode it via the
	// production cwtPayload struct tags. If the struct tags (65533/65534/...) ever
	// diverge from spec, lst/ttl won't populate and this fails.
	payload := map[int64]any{
		spec.ClaimSub:        "https://issuer.example/list/1",
		spec.ClaimIat:        int64(1000),
		spec.ClaimTTL:        int64(3600),
		spec.ClaimStatusList: map[string]any{"bits": 1, "lst": []byte{0x78, 0x9c, 0x01}},
	}
	raw, err := cbor.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	cl, err := decodeCWTClaims(raw)
	if err != nil {
		t.Fatalf("decodeCWTClaims: %v", err)
	}
	if cl.Sub != "https://issuer.example/list/1" || cl.TTL != 3600 || len(cl.Lst) == 0 {
		t.Fatalf("spec keys do not match wire tags: %+v", cl)
	}
}
