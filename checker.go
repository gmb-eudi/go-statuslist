package statuslist

import (
	"context"
	stdcrypto "crypto"
	"fmt"
	"time"
)

// Fetcher retrieves a status list / identifier list document by URI. In
// services it wraps the platform-kit httpclient (correlation propagation); in
// tests it is a fake with no network (framework-free; no network in
// unit tests).
type Fetcher interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// Cache is an opaque, TTL-aware byte cache for fetched lists. It enforces its
// own expiry: Get returns ok=false once an entry's ttl has elapsed.
type Cache interface {
	Get(key string) ([]byte, bool)
	Set(key string, val []byte, ttl time.Duration)
}

// KeyResolver resolves the verification key of a status list token's issuer.
// It is injected so trust-anchor resolution stays in the trust layer:
// go-statuslist never dereferences jku/x5u/kid to fetch keys. It
// receives the list URI and the raw (unverified) token, from which a trust
// resolver may read the kid / x5c header to select the key.
type KeyResolver func(ctx context.Context, listURI string, token []byte) (stdcrypto.PublicKey, error)

// CheckInput is one revocation query.
type CheckInput struct {
	Ref               StatusRef
	IssuerKeyResolver KeyResolver
	Policy            Policy
	// CredentialValidity is the referenced credential's remaining technical
	// validity. When 0 < CredentialValidity < ShortLivedThreshold the check is
	// skipped (ARF Topic 7 VCR_01). Zero means "unknown" ⇒ never skip.
	CredentialValidity time.Duration
}

// Checker performs revocation checks. Construct with NewChecker.
type Checker struct {
	fetcher         Fetcher
	cache           Cache
	now             func() time.Time
	maxDecompressed int
	clockSkew       time.Duration
}

// Option configures a Checker.
type Option func(*Checker)

// WithClock injects the clock used for exp/ttl/short-lived reasoning
// (no wall clock). Ignored if nil.
func WithClock(clk func() time.Time) Option {
	return func(c *Checker) {
		if clk != nil {
			c.now = clk
		}
	}
}

// WithMaxDecompressed overrides the inflated-size cap (zip-bomb defence).
// Values <= 0 are ignored.
func WithMaxDecompressed(n int) Option {
	return func(c *Checker) {
		if n > 0 {
			c.maxDecompressed = n
		}
	}
}

// WithClockSkew tolerates a clock difference between issuer and verifier when
// checking iat (not-in-future) and exp ([Token Status List §5]). It is distinct from
// Policy.MaxStale, which is a deliberate staleness grace beyond exp; the two
// compose. Values < 0 are ignored.
func WithClockSkew(d time.Duration) Option {
	return func(c *Checker) {
		if d >= 0 {
			c.clockSkew = d
		}
	}
}

// NewChecker returns a Checker. cache may be nil (caching disabled).
func NewChecker(fetcher Fetcher, cache Cache, opts ...Option) *Checker {
	c := &Checker{
		fetcher:         fetcher,
		cache:           cache,
		now:             time.Now,
		maxDecompressed: DefaultMaxDecompressed,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Check resolves the revocation status of the referenced credential. Fail
// closed by default: an inconclusive result returns
// StatusUnknown with a non-nil error unless the client policy explicitly opts
// into fail-open (Policy.AllowFailOpen == true).
//
// The ARF Topic 7 VCR_01 short-lived exemption is applied first, before any
// fetch (Task 6).
func (c *Checker) Check(ctx context.Context, in CheckInput) (Status, Provenance, error) {
	prov := Provenance{
		URI:       in.Ref.URI,
		Index:     in.Ref.Index,
		ID:        in.Ref.ID,
		CheckedAt: c.now(),
	}
	// ARF Topic 7 VCR_01: a credential valid for less than ShortLivedThreshold
	// (24h; origin ETSI EN 319 411-1 v1.4.1 REV-6.2.4-03A) is exempt from
	// revocation checking. Skip before any fetch. Zero validity = unknown ⇒
	// never skip.
	if in.CredentialValidity > 0 && in.CredentialValidity < ShortLivedThreshold {
		prov.Outcome = OutcomeSkippedShortLived
		return StatusSkippedShortLived, prov, nil
	}
	switch in.Ref.Kind {
	case RefTokenStatusList:
		return c.checkTokenStatusList(ctx, in, prov)
	case RefIdentifierList:
		return c.checkIdentifierList(ctx, in, prov)
	default:
		return c.failClosed(in.Policy, prov, fmt.Errorf("%w: ref kind %d", ErrUnsupported, in.Ref.Kind))
	}
}

// failClosed applies the policy to an inconclusive result. Fail-closed
// (default, the zero value) surfaces the cause; the explicit per-client
// fail-open flag (AllowFailOpen == true) records the skip in Provenance and
// returns no error.
func (c *Checker) failClosed(p Policy, prov Provenance, cause error) (Status, Provenance, error) {
	if !p.AllowFailOpen {
		prov.Outcome = OutcomeUnavailable
		return StatusUnknown, prov, cause
	}
	prov.Outcome = OutcomeSkippedFailOpen
	prov.FailOpen = true
	return StatusUnknown, prov, nil
}

// cacheTTL derives the cache lifetime from the token's ttl claim (seconds) and
// exp (absolute). ttl is the maximum caching time before a refresh (Token
// [Token Status List §8]); exp caps it — never cache past the token's own expiry.
// Returns 0 when neither is present ⇒ do not cache.
func cacheTTL(ttl, exp int64, now time.Time) time.Duration {
	best := time.Duration(-1)
	if ttl > 0 {
		best = time.Duration(ttl) * time.Second
	}
	if exp > 0 {
		if until := time.Unix(exp, 0).Sub(now); until > 0 && (best < 0 || until < best) {
			best = until
		}
	}
	if best < 0 {
		return 0
	}
	return best
}

// maybeCache stores a freshly fetched, verified list under its derived TTL. A
// cache-served list is not re-stored.
func (c *Checker) maybeCache(uri string, raw []byte, ttl, exp int64, fromCache bool) {
	if c.cache == nil || fromCache {
		return
	}
	if d := cacheTTL(ttl, exp, c.now()); d > 0 {
		c.cache.Set(uri, raw, d)
	}
}

// applyFreshness enforces the token's iat (not issued in the future, RFC 8392)
// and exp ([Token Status List §5]) against the clock. ClockSkew tolerates clock differences on
// both; Policy.MaxStale is an additional deliberate grace beyond exp (within the
// grace, prov.Stale=true; past exp+MaxStale+skew, ErrExpired). exp==0 ⇒ no
// token-level expiry (ttl still bounds caching, Task 7); iat==0 ⇒ no iat check.
func (c *Checker) applyFreshness(iat, exp int64, p Policy, prov *Provenance) error {
	now := c.now()
	if iat != 0 && time.Unix(iat, 0).After(now.Add(c.clockSkew)) {
		return fmt.Errorf("%w: iat ahead of now+skew", ErrIssuedInFuture)
	}
	if exp == 0 {
		return nil
	}
	expTime := time.Unix(exp, 0)
	if now.After(expTime.Add(p.MaxStale).Add(c.clockSkew)) {
		return fmt.Errorf("%w: exp+MaxStale+skew elapsed", ErrExpired)
	}
	if now.After(expTime) {
		prov.Stale = true
	}
	return nil
}
