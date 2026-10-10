# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.1.6

**Requires Go 1.27.2.** The `go` directive moves up from 1.26.6, so a consumer on an older
toolchain will not build this version. Go 1.27.2 is a security release, and under Go 1.27.0 this
library's code reaches four standard-library vulnerabilities, all in `net/http`: GO-2026-6603, -6611, -6613 and -6617. No source, no signature and no message text changed.

### Changed

- **`go` directive 1.26.6 → 1.27.2**, the minimum Go version a consumer needs. Under 1.27.2
  `govulncheck` finds no vulnerability this library calls. Raise your own module's `go` directive
  to `1.27.2`; from there the go command downloads and uses that toolchain by itself.
- **`go-eudi-crypto` → v0.0.9** (was v0.0.8), its own move to Go 1.27.2 with no code change.
- `fxamacker/cbor/v2` → **v2.9.6** (was v2.9.3), the CBOR codec its status lists are read with.

### Notes

- **Indirect modules moved:** `goccy/go-json` → v0.11.2, `golang.org/x/crypto` → v0.58.0, `golang.org/x/sys` → v0.49.0.

- The README's "Requires Go 1.26" line moved with the directive; it says Go 1.27, which still holds.

- The gate is green on Go 1.27.2: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  golangci-lint v2.14.0, `go test -race` with **0 races**, and all four fuzz targets for 30 seconds
  each with no failing input. `govulncheck` reports **no vulnerabilities found** at any level, the
  module-level `golang.org/x/crypto/openpgp` advisory (GO-2026-5932) included.

- Repository hygiene, with no effect on code that uses the library: CI's linter moved to
  golangci-lint v2.14.0 (the earlier release cannot read Go 1.27.2's compiled standard library).

## v0.1.5

Dependency maintenance. No source changed here and nothing this library does behaves differently.

### Notes

- **`github.com/gmb-eudi/go-eudi-crypto` → v0.0.8** (was v0.0.7). That release changed no source of
  its own either — it took `github.com/lestrrat-go/jwx/v3` to **v3.3.0** and `golang.org/x/crypto`
  to **v0.57.0**. Both reach this library only through it: **nothing here imports jwx**, it arrives
  as an indirect requirement. The `x/crypto` move crosses the release that fixed **GO-2026-6354**
  and **GO-2026-6355** upstream.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` with **0 races**; `govulncheck` finds nothing.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes to
  `develop`, the pinned GitHub Actions moved to their current commits, the `setup-go` pin rolled forward, and a stray comment was dropped from `.gitattributes`.

## v0.1.4

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **Errors now wrap their cause as well as their sentinel — 11 sites** in `cwt.go`,
  `identifier.go` and `token.go`. Each was built as `fmt.Errorf("%w: …: %v", ErrSentinel, err)`:
  the sentinel wrapped, the cause printed into the string and then unreachable. Both are now
  `%w`.

  This is the change most worth having in this library, because the sentinels here answer
  *which stage* failed and the cause answers *why* — and a relying party treats those
  differently. A status list that could not be **fetched** is a transient network or hosting
  problem; one whose signature does not **verify** is a trust problem:

  ```go
  if errors.Is(err, ErrFetch) {
      var netErr net.Error
      if errors.As(err, &netErr) && netErr.Timeout() { /* retry */ }
  }
  ```

  `errors.Is(err, ErrFetch)` / `ErrVerify` / `ErrMalformed` / `ErrKeyUnresolved` /
  `ErrDecompress` all still hold and every rendered message is byte-identical (`%v` and `%w`
  print an error the same way), so no existing caller needs to change.

### Dependencies

- `go-eudi-crypto` v0.0.5 → v0.0.6.
- `github.com/fxamacker/cbor/v2` v2.9.2 → v2.9.3, `golang.org/x/crypto` v0.54.0 → v0.55.0
  (indirect), `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect).

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.
