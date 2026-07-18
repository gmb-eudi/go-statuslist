package statuslist_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sl "github.com/gmb-eudi/go-statuslist"
)

// fakeCache records the last Set and serves a fixed Get result (no clock — the
// Checker never asks the cache for age; a fresh entry ⇒ ok=true, an
// expired/absent entry ⇒ ok=false, mirroring a real TTL cache).
type fakeCache struct {
	getVal []byte
	getOK  bool
	setKey string
	setVal []byte
	setTTL time.Duration
	sets   int
}

func (c *fakeCache) Get(string) ([]byte, bool) { return c.getVal, c.getOK }
func (c *fakeCache) Set(k string, v []byte, ttl time.Duration) {
	c.setKey, c.setVal, c.setTTL = k, v, ttl
	c.sets++
}

// A fresh cache entry short-circuits the fetch; the served list is
// re-verified and reported as cached.
func TestCacheHitAvoidsFetch(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Unix(), ttl: 3600, bits: 1, statuses: []int{0, 1}})
	cache := &fakeCache{getVal: tok, getOK: true}
	f := &fakeFetcher{err: errors.New("must not be called")}
	c := sl.NewChecker(f, cache, fixedClock())

	st, prov, err := c.Check(context.Background(), sl.CheckInput{
		Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
	})
	if err != nil || st != sl.StatusRevoked {
		t.Fatalf("st=%v err=%v, want StatusRevoked", st, err)
	}
	if f.calls != 0 {
		t.Errorf("fetcher called %d times on cache hit, want 0", f.calls)
	}
	if !prov.FromCache || prov.Outcome != sl.OutcomeCached {
		t.Errorf("prov = %+v, want FromCache=true Outcome=checked-cached", prov)
	}
	if cache.sets != 0 {
		t.Errorf("cache.Set called %d times on cache hit, want 0", cache.sets)
	}
}

// An expired/absent cache entry (Get ok=false) triggers a refetch, and
// the fresh list is cached with a TTL derived from the token.
func TestCacheMissFetchesAndCaches(t *testing.T) {
	ti := newTestIssuer(t)
	tests := []struct {
		name    string
		ttl     int64
		exp     int64
		wantTTL time.Duration
		wantSet bool
	}{
		{"ttl only", 3600, 0, 3600 * time.Second, true},
		{"exp tighter than ttl", 7200, epoch.Add(time.Hour).Unix(), time.Hour, true},
		{"exp only", 0, epoch.Add(30 * time.Minute).Unix(), 30 * time.Minute, true},
		{"neither ⇒ not cached", 0, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok := ti.jwt(t, tokenOpts{sub: listURI, iat: epoch.Unix(), ttl: tc.ttl, exp: tc.exp, bits: 1, statuses: []int{0, 1}})
			cache := &fakeCache{getOK: false}
			f := &fakeFetcher{body: tok}
			c := sl.NewChecker(f, cache, fixedClock())
			st, prov, err := c.Check(context.Background(), sl.CheckInput{
				Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(),
				Policy: sl.Policy{AllowFailOpen: false, MaxStale: 2 * time.Hour},
			})
			if err != nil || st != sl.StatusRevoked {
				t.Fatalf("st=%v err=%v", st, err)
			}
			if f.calls != 1 {
				t.Errorf("fetcher calls = %d, want 1 (refetch on miss)", f.calls)
			}
			if prov.FromCache {
				t.Error("prov.FromCache = true on a miss")
			}
			if tc.wantSet {
				if cache.sets != 1 {
					t.Fatalf("cache.sets = %d, want 1", cache.sets)
				}
				if cache.setTTL != tc.wantTTL {
					t.Errorf("cache TTL = %v, want %v", cache.setTTL, tc.wantTTL)
				}
				if cache.setKey != listURI {
					t.Errorf("cache key = %q, want %q", cache.setKey, listURI)
				}
			} else if cache.sets != 0 {
				t.Errorf("cache.sets = %d, want 0 (no ttl/exp ⇒ do not cache)", cache.sets)
			}
		})
	}
}

// Refetch failure honours policy.
func TestRefetchFailureHonorsPolicy(t *testing.T) {
	ti := newTestIssuer(t)
	t.Run("fail-closed", func(t *testing.T) {
		c := sl.NewChecker(&fakeFetcher{err: errors.New("down")}, &fakeCache{getOK: false}, fixedClock())
		_, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
		})
		if !errors.Is(err, sl.ErrFetch) || prov.Outcome != sl.OutcomeUnavailable {
			t.Fatalf("err=%v prov=%+v", err, prov)
		}
	})
	t.Run("fail-open", func(t *testing.T) {
		c := sl.NewChecker(&fakeFetcher{err: errors.New("down")}, &fakeCache{getOK: false}, fixedClock())
		st, prov, err := c.Check(context.Background(), sl.CheckInput{
			Ref: tokenRef(1), IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: true},
		})
		if err != nil || st != sl.StatusUnknown || !prov.FailOpen {
			t.Fatalf("st=%v prov=%+v err=%v", st, prov, err)
		}
	})
}

// The identifier list uses the same cache path.
func TestIdentifierListCaches(t *testing.T) {
	ti := newTestIssuer(t)
	tok := ti.idJWT(t, idListOpts{sub: idListURI, iat: epoch.Unix(), ttl: 1800, ids: []string{"urn:cred:aaa"}})
	cache := &fakeCache{getOK: false}
	c := sl.NewChecker(&fakeFetcher{body: tok}, cache, fixedClock())
	st, _, err := c.Check(context.Background(), sl.CheckInput{
		Ref:               sl.StatusRef{Kind: sl.RefIdentifierList, URI: idListURI, ID: "urn:cred:aaa"},
		IssuerKeyResolver: ti.resolver(), Policy: sl.Policy{AllowFailOpen: false},
	})
	if err != nil || st != sl.StatusRevoked {
		t.Fatalf("st=%v err=%v", st, err)
	}
	if cache.sets != 1 || cache.setTTL != 1800*time.Second {
		t.Errorf("cache set=%d ttl=%v, want 1 / 1800s", cache.sets, cache.setTTL)
	}
}
