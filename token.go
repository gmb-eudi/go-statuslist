package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// checkTokenStatusList implements the IETF Token Status List mechanism
// (draft-ietf-oauth-status-list): load the Status List Token (cache-preferred,
// Task 7), verify its signature via the injected resolver + go-eudi-crypto
// (hard rule 4), decode the claims, bind the token's sub to the referenced
// list URI (Task 4), enforce the token's exp with a MaxStale grace (Task 6),
// cache the freshly fetched raw token under a ttl/exp-derived lifetime (Task
// 7), inflate the status list under a size cap, and read the entry at the
// referenced index.
func (c *Checker) checkTokenStatusList(ctx context.Context, in CheckInput, prov Provenance) (Status, Provenance, error) {
	prov.Mechanism = "token-status-list"
	raw, fromCache, err := c.load(ctx, in.Ref.URI)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	prov.FromCache = fromCache
	payload, format, err := c.verifyToken(ctx, in, raw)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	prov.Format = format
	claims, err := decodeClaims(format, payload)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	// Token Status List §5: the Status List Token's sub MUST equal the uri of
	// the Status List reference in the credential (StatusRef.URI). Reject a
	// valid-but-wrong list substituted for the referenced one. URIs are
	// identifiers, not attribute values (hard rule 3).
	if claims.Sub != in.Ref.URI {
		return c.failClosed(in.Policy, prov, fmt.Errorf("%w: token sub=%q ref uri=%q", ErrSubMismatch, claims.Sub, in.Ref.URI))
	}
	if err := c.applyFreshness(claims.Exp, in.Policy, &prov); err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	c.maybeCache(in.Ref.URI, raw, claims.TTL, claims.Exp, prov.FromCache)
	prov.Bits = claims.Bits
	lst, err := c.inflate(claims.Lst)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	value, err := statusAt(lst, claims.Bits, in.Ref.Index)
	if err != nil {
		return c.failClosed(in.Policy, prov, err)
	}
	if prov.FromCache {
		prov.Outcome = OutcomeCached
	} else {
		prov.Outcome = OutcomeChecked
	}
	return mapStatus(value), prov, nil
}

// load retrieves the raw list document, preferring a fresh cache entry. The
// Cache enforces its own TTL (Get returns ok=false once expired), so an
// expired/absent entry falls through to a network refetch (Token Status List
// §8 caching; ARF Topic 7 VCR guidance: cache, refetch when stale).
func (c *Checker) load(ctx context.Context, uri string) (raw []byte, fromCache bool, err error) {
	if c.cache != nil {
		if cached, ok := c.cache.Get(uri); ok && len(cached) > 0 {
			return cached, true, nil
		}
	}
	body, ferr := c.fetcher.Get(ctx, uri)
	if ferr != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrFetch, ferr)
	}
	if len(body) == 0 {
		return nil, false, fmt.Errorf("%w: empty document", ErrFetch)
	}
	return body, false, nil
}

// verifyToken resolves the issuer key and verifies the Status List Token
// signature via go-eudi-crypto. It returns the verified payload and a format
// tag ("jwt"/"cwt").
func (c *Checker) verifyToken(ctx context.Context, in CheckInput, raw []byte) (payload []byte, format string, err error) {
	if in.IssuerKeyResolver == nil {
		return nil, "", fmt.Errorf("%w: no resolver supplied", ErrKeyUnresolved)
	}
	key, kerr := in.IssuerKeyResolver(ctx, in.Ref.URI, raw)
	if kerr != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrKeyUnresolved, kerr)
	}
	if resolveFormat(in.Ref.Format, raw) == FormatJWT {
		// Token Status List §5.1: statuslist+jwt, verified as a compact JWS.
		p, _, verr := eudicrypto.VerifyJWS(raw, key)
		if verr != nil {
			return nil, "jwt", fmt.Errorf("%w: %v", ErrVerify, verr)
		}
		return p, "jwt", nil
	}
	// Token Status List §5.2: application/statuslist+cwt, verified as COSE_Sign1.
	p, _, verr := eudicrypto.VerifyCOSESign1(raw, key)
	if verr != nil {
		return nil, "cwt", fmt.Errorf("%w: %v", ErrVerify, verr)
	}
	return p, "cwt", nil
}

// resolveFormat honours an explicit StatusRef.Format, else sniffs: a compact
// JWS (§5.1) is ASCII with exactly two '.' separators and base64url segments;
// anything else is CBOR (CWT, §5.2).
func resolveFormat(f TokenFormat, raw []byte) TokenFormat {
	switch f {
	case FormatJWT:
		return FormatJWT
	case FormatCWT:
		return FormatCWT
	case FormatAuto:
		if looksLikeJWS(raw) {
			return FormatJWT
		}
		return FormatCWT
	default:
		if looksLikeJWS(raw) {
			return FormatJWT
		}
		return FormatCWT
	}
}

func looksLikeJWS(raw []byte) bool {
	if bytes.Count(raw, []byte(".")) != 2 {
		return false
	}
	for _, b := range raw {
		switch {
		case b == '.':
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_':
		default:
			return false
		}
	}
	return true
}

// statusListClaims is the format-independent view of the Status List Token
// claims (draft-ietf-oauth-status-list §5). Lst is still zlib-compressed.
type statusListClaims struct {
	Sub  string
	Iat  int64
	Exp  int64 // 0 = absent
	TTL  int64 // 0 = absent
	Bits int
	Lst  []byte
}

// decodeClaims decodes the verified token payload.
func decodeClaims(format string, payload []byte) (statusListClaims, error) {
	switch format {
	case "jwt":
		return decodeJWTClaims(payload)
	case "cwt":
		return decodeCWTClaims(payload)
	default:
		return statusListClaims{}, fmt.Errorf("%w: claims for format %q", ErrUnsupported, format)
	}
}

// jwtPayload mirrors the JSON Status List Token claims (§5.1). Standard JWT
// claims (iss/aud/nbf/...) are legitimately present and ignored — do NOT reject
// unknown members here (this is a foreign token, not our own).
type jwtPayload struct {
	Sub        string `json:"sub"`
	Iat        int64  `json:"iat"`
	Exp        *int64 `json:"exp"`
	TTL        *int64 `json:"ttl"`
	StatusList struct {
		Bits int    `json:"bits"`
		Lst  string `json:"lst"` // base64url, zlib-compressed
	} `json:"status_list"`
}

func decodeJWTClaims(payload []byte) (statusListClaims, error) {
	var p jwtPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return statusListClaims{}, fmt.Errorf("%w: json claims: %v", ErrMalformed, err)
	}
	if p.StatusList.Lst == "" {
		return statusListClaims{}, fmt.Errorf("%w: missing status_list.lst", ErrMalformed)
	}
	lst, err := base64.RawURLEncoding.DecodeString(p.StatusList.Lst)
	if err != nil {
		if lst, err = base64.URLEncoding.DecodeString(p.StatusList.Lst); err != nil {
			return statusListClaims{}, fmt.Errorf("%w: status_list.lst base64url: %v", ErrMalformed, err)
		}
	}
	cl := statusListClaims{Sub: p.Sub, Iat: p.Iat, Bits: p.StatusList.Bits, Lst: lst}
	if p.Exp != nil {
		cl.Exp = *p.Exp
	}
	if p.TTL != nil {
		cl.TTL = *p.TTL
	}
	return cl, nil
}

// inflate decompresses a zlib (RFC 1950) byte array, capping output at
// c.maxDecompressed to defend against decompression bombs (hard rule 5). Memory
// is bounded to cap+1 bytes regardless of input.
func (c *Checker) inflate(compressed []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecompress, err)
	}
	defer func() { _ = zr.Close() }()
	limit := int64(c.maxDecompressed)
	out, err := io.ReadAll(io.LimitReader(zr, limit+1)) //nolint:gosec // G110: bounded by LimitReader(cap+1) and the len>cap check below
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecompress, err)
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("%w: > %d bytes", ErrDecompressTooBig, c.maxDecompressed)
	}
	return out, nil
}

// statusAt reads the status value at index i. Entries are packed little-endian
// within each byte: index 0 occupies the least-significant bits
// (draft-ietf-oauth-status-list §4).
func statusAt(lst []byte, bits, index int) (int, error) {
	switch bits {
	case 1, 2, 4, 8:
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnknownBitWidth, bits)
	}
	if index < 0 {
		return 0, fmt.Errorf("%w: negative index %d", ErrIndexOutOfRange, index)
	}
	perByte := 8 / bits
	byteIdx := index / perByte
	if byteIdx >= len(lst) {
		return 0, fmt.Errorf("%w: index %d, list holds %d entries", ErrIndexOutOfRange, index, len(lst)*perByte)
	}
	shift := uint((index % perByte) * bits)
	mask := (1 << bits) - 1
	return int(lst[byteIdx]>>shift) & mask, nil
}
