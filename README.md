# go-statuslist

Credential **revocation checking** for EUDI Wallet relying-party components, in
one small, framework-free Go module.

It resolves whether a presented credential has been revoked, using the two
mechanisms an EUDI Relying Party that checks revocation must support
(ARF 2.9 Topic 7, VCR_02):

- **IETF Token Status List** status list tokens, in both **JWT** and **CWT**
  form (`draft-ietf-oauth-status-list`): signature verification, `sub` binding
  to the referenced list, zlib decompression under a strict output-size cap,
  bit widths 1/2/4/8, and index lookup.
- **ARF Attestation Revocation List** ("Identifier List"): a signed token
  enumerating revoked credential identifiers — listed ⇒ revoked, absent ⇒ valid.

It is deliberately small and unopinionated about I/O: you inject an HTTP
`Fetcher`, an optional `Cache`, a clock, and a `KeyResolver`; the library owns
only the parsing, verification orchestration, and revocation policy.

```
import "github.com/gmb-eudi/go-statuslist"
```

Requires Go 1.26. Sole runtime dependencies: `github.com/gmb-eudi/go-eudi-crypto`
(all JOSE/COSE verification) and `github.com/fxamacker/cbor/v2` (hardened CWT
decoding).

## Quick start

```go
package main

import (
	"context"
	"crypto"
	"io"
	"net/http"
	"time"

	statuslist "github.com/gmb-eudi/go-statuslist"
)

// A Fetcher over the standard library (services inject the platform httpclient).
type httpFetcher struct{ c *http.Client }

func (f httpFetcher) Get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func main() {
	checker := statuslist.NewChecker(
		httpFetcher{c: http.DefaultClient},
		nil, // optional Cache; nil disables caching
	)

	// The issuer key is resolved through your trust layer. go-statuslist never
	// dereferences jku/x5u/kid itself — it hands you the list URI and the raw
	// (unverified) token so your resolver can pick the right key.
	resolve := func(ctx context.Context, listURI string, token []byte) (crypto.PublicKey, error) {
		return myTrustLayer.KeyFor(ctx, listURI, token)
	}

	status, prov, err := checker.Check(context.Background(), statuslist.CheckInput{
		Ref: statuslist.StatusRef{
			Kind:  statuslist.RefTokenStatusList,
			URI:   "https://issuer.example/statuslists/1",
			Index: 42,
		},
		IssuerKeyResolver:  resolve,
		Policy:             statuslist.Policy{FailClosed: true},
		CredentialValidity: 90 * 24 * time.Hour, // remaining validity of the credential being checked
	})
	// err != nil under a fail-closed policy when the status can't be established.
	// status is one of the values below; prov records how the verdict was reached.
	_ = status
	_ = prov
	_ = err
}
```

For the second mechanism, set `Kind: RefIdentifierList` and provide the credential
identifier in `StatusRef.ID` instead of `Index`.

## Results

`Check` returns `(Status, Provenance, error)`.

| `Status` | `.String()` | Meaning |
|---|---|---|
| `StatusValid` | `valid` | List entry `0x00` — not revoked. |
| `StatusRevoked` | `revoked` | List entry `0x01` — revoked. |
| `StatusSuspended` | `suspended` | List entry `0x02` — temporarily invalid. |
| `StatusUnknown` | `unknown` | Status could not be established, **or** the entry held an unrecognized value. Treat as **not valid**. |
| `StatusSkippedShortLived` | `skipped-short-lived` | The check was legitimately skipped (short-lived exemption, below). Not a Token Status List value. |

`Provenance` is a value-free record of *how* the verdict was reached — mechanism,
list URI, format (`jwt`/`cwt`), index or id, bit width, an `Outcome` string
(`checked`, `checked-cached`, `skipped-short-lived`, `skipped-fail-open`,
`unavailable`), and the `FromCache` / `Stale` / `FailOpen` / `CheckedAt` flags.
It carries only identifiers and enums — never a credential attribute value — and
is meant to be embedded verbatim in a verification report.

> **Suspended** is reported as its own `StatusSuspended`. Callers that treat
> suspension as (temporary) invalidity should map it accordingly — e.g.
> verifier-core maps it to `err:revocation:revoked` with a `suspended=true`
> detail.

## Policy: fail-closed vs fail-open

`Policy` governs what happens when a status **cannot be established** (fetch
failure, signature failure, `sub` mismatch, malformed/oversized list, unknown
bit width, out-of-range index, or expiry beyond the stale grace):

```go
type Policy struct {
	FailClosed bool          // true  → inconclusive status returns a typed error
	MaxStale   time.Duration // grace beyond a token's exp (see below)
}
```

- **`Policy{FailClosed: true}`** — an inconclusive result returns
  `StatusUnknown` **and a non-nil typed error** (`Outcome: unavailable`). This is
  the safe posture and what production callers should use.
- **`Policy{FailClosed: false}`** — an inconclusive result is a recorded
  *skip*: `StatusUnknown`, **no error**, `Outcome: skipped-fail-open`,
  `FailOpen: true`. This is a deliberate per-client opt-out and it is surfaced in
  the verification report. Even under fail-open, a `sub` mismatch or a revoked
  entry is **never** reported as a real status — the substitution/revocation
  defences hold.

> ⚠️ **The `Policy` zero value is fail-open.** `FailClosed`'s Go zero value is
> `false`, so a `Policy{}` (or an unset field) skips fail-closed enforcement.
> Always set `FailClosed: true` explicitly for the safe posture. (This ergonomics
> wrinkle is under review for pre-v1; the field may be reshaped so the zero value
> is the safe one.)

## Short-lived exemption

ARF Topic 7 VCR_01 exempts credentials with a validity of **24 hours or less**
from revocation checking (the 24 h originates from ETSI EN 319 411-1). Pass the
credential's remaining validity in `CheckInput.CredentialValidity`; when
`0 < CredentialValidity < 24h`, `Check` returns `StatusSkippedShortLived`
**before any fetch**, recorded as `Outcome: skipped-short-lived`. A zero
`CredentialValidity` means "unknown" and never skips.

## Caching and freshness

Provide a `Cache` to `NewChecker` to avoid refetching a list on every check:

```go
type Cache interface {
	Get(key string) ([]byte, bool)          // ok=false once the entry's TTL has elapsed
	Set(key string, val []byte, ttl time.Duration)
}
```

- A **cache hit short-circuits the fetch** but is **still fully re-verified**
  (signature, `sub` binding, freshness) on every call — the cache holds raw
  signed bytes, never a trusted verdict.
- After a successful fresh check the list is cached with a TTL derived from the
  token's `ttl` claim, clamped by its `exp`. If the token carries neither, it is
  not cached.
- **`Policy.MaxStale`** is the grace beyond a token's own `exp` during which a
  served list is still accepted (marked `Stale: true` in provenance). Past
  `exp + MaxStale` the list is treated as unavailable (`ErrExpired`, honouring
  `FailClosed`).

## Construction options

```go
func NewChecker(fetcher Fetcher, cache Cache, opts ...Option) *Checker

func WithClock(func() time.Time) Option        // inject the clock (exp/ttl/short-lived reasoning); tests use a fixed clock
func WithMaxDecompressed(n int) Option          // override the inflated-list size cap (default DefaultMaxDecompressed = 1 MiB)
```

## How a check works

Both mechanisms share one pipeline; every step fails closed by default:

1. **load** — a fresh cache entry, else fetch via the injected `Fetcher`.
2. **verify** — the signature is checked by `go-eudi-crypto`
   (`VerifyJWS` for JWT, `VerifyCOSESign1` for CWT) using the key returned by
   your `KeyResolver`. The token format is taken from `StatusRef.Format`
   (`FormatJWT`/`FormatCWT`) or sniffed (`FormatAuto`).
3. **sub binding** — the token's `sub` must equal `StatusRef.URI`, so a
   valid-but-wrong list cannot be substituted for the referenced one.
4. **freshness** — `exp` is enforced with the `MaxStale` grace.
5. **decode + read** — status list: zlib-inflate under the size cap, then read
   the little-endian entry at `Index`. Identifier list: membership test on `ID`.

Nothing is trusted before the signature is verified, and the MSO/claims are read
only from the verified payload.

## Errors

Verification-relevant failures are wrapped, typed sentinels (compare with
`errors.Is`); services map them to problem codes such as
`err:revocation:revoked` / `err:revocation:unavailable`:

`ErrUnsupported`, `ErrFetch`, `ErrKeyUnresolved`, `ErrVerify`, `ErrMalformed`,
`ErrSubMismatch`, `ErrUnknownBitWidth`, `ErrIndexOutOfRange`, `ErrDecompress`,
`ErrDecompressTooBig`, `ErrExpired`.

Errors carry only identifiers (list URIs, indices, credential identifiers, kids),
bit widths and outcome enums — **never** a credential attribute value.

## Design

- **Framework-free** (no web framework, no logging, no direct HTTP): `Fetcher`,
  `Cache`, the clock, and the `KeyResolver` are all injected. In services the
  fetcher wraps the platform HTTP client; in tests it is a fake with no network.
- **Crypto is centralized**: all JOSE/COSE verification is delegated to
  `go-eudi-crypto`; this module names no algorithms or curves.
- **Trust stays in the trust layer**: key resolution is the injected
  `KeyResolver`'s job — go-statuslist never dereferences `jku`/`x5u`/`kid` to
  fetch keys.
- **Hardened parsing**: untrusted CBOR is decoded with a bounded `DecMode`
  (nesting/size caps, duplicate-key reject, indefinite-length and tags
  forbidden); zlib inflation is capped to bound memory against decompression
  bombs. The decoders and the inflate path have fuzz targets and never panic on
  malformed input.
- **No attribute values** ever appear in errors, provenance, logs or traces.

## Specification conformance and open items

Implemented against `draft-ietf-oauth-status-list` (Token Status List, JWT + CWT),
RFC 7515 (JWS), RFC 9052 / RFC 8392 (COSE_Sign1 / CWT), RFC 1950/1951 (zlib), and
ARF 2.9 Topic 7 (VCR_01/02/11/13). See [`SPECREFS.md`](SPECREFS.md) for pinned
versions.

Pre-v1 caveats, tracked in `SPECREFS.md`:

- The status-list draft is not yet vendored; the CWT private claim keys used
  (`status_list` = 65533, `ttl` = 65534, `typ` header label 16) must be
  confirmed against the pinned draft.
- The **Attestation Revocation List wire format** (payload `sub`/`iat`/`exp`/`ttl`
  + `identifier_list.ids`, CBOR private claim key 65532) is a documented interim
  choice; the Commission TS referenced by ARF VCR_11 is not yet vendored and the
  shape must be verified before v1.

**Status: pre-v1.** The public API is not frozen before an OIDF/interoperability
conformance pass.

## License

MIT — see [`LICENSE`](LICENSE).
