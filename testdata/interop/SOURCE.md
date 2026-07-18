# interop test vectors

Cross-repo regression fixtures for `interop_test.go`. These two files are real
Status List Tokens produced ONCE by the issuer service
`github.com/unknovs/status-list-go` (checked out at
`references/status-list-go` in the verifier workspace), via its
`services.StatusListFormatter.GenerateJWT` / `GenerateCWT` formatters. They exist
so go-statuslist has a permanent proof it can verify real GO-SRV output, not just
its own in-test issuer's synthetic vectors (`issuer_test.go`, ADR-0007).

| file | format | media type |
| ---- | ------ | ---------- |
| `status-list-go.asl.jwt` | Token Status List §5.1 | `statuslist+jwt` |
| `status-list-go.asl.cwt` | Token Status List §5.2 | `application/statuslist+cwt` |

## Parameters (the answer key `interop_test.go` asserts)

* `bits = 1`, `size = 16`, strategy `sequential`
  (`models.NewIssuerStatusList(1, 16, "sequential")`)
* index **3** set revoked (`StatusList.Set(3, 1)`); index **0** left VALID (0)
* list URI (`sub`): `https://status-list-go.test/interop/1`
* expiry (`exp`): `2035-01-01`
* `ttl`: 3600

## Clock / freshness

These are frozen bytes, so `interop_test.go` pins the `Checker`'s clock to a fixed
instant (`2030-01-01`, via `statuslist.WithClock`) that sits inside the fixtures'
`[iat (~mid-2026), exp (2035-01-01)]` window. That keeps this permanent regression
net verifying the exact committed bytes on their own merits forever — with the real
wall clock it would begin failing with `ErrExpired` after 2035-01-01 and from then
on mask any real wire-format regression behind an unrelated expiry error.

## Keys / trust

NOT a production key. Each token is signed with a fresh, ephemeral, test-only
ECDSA P-256 self-signed certificate, and that certificate is embedded in the
token's OWN header — `x5c` (RFC 7515 §4.1.6, standard base64) for the JWT,
`x5chain` (COSE protected header label 33, array form) for the CWT. The fixtures
are therefore self-describing: `interop_test.go` extracts the issuer public key
straight out of each token's header, so no separate key/cert file is committed.
The test intentionally skips trust-anchor validation (hard rule 6 governs
production code, not a self-contained test fixture).

## Regenerating

If a future status-list-go wire-format change requires new fixtures, regenerate
the SAME way (do not hand-edit these binaries):

1. In `references/status-list-go/services`, add a throwaway
   `*_test.go` that calls `newTestKeyCert`, builds the status list with the
   parameters above, calls `GenerateJWT` / `GenerateCWT`, and writes the raw
   bytes here with `os.WriteFile`.
2. Run it once
   (`GEN_INTEROP_FIXTURES=1 GOWORK=off go test ./services/ -run <name> -v`),
   confirm both files are non-empty, then DELETE the generator (a file that only
   writes fixtures asserts nothing and must not linger in the suite).
3. Re-run `go test ./...` here so `interop_test.go` re-verifies the new fixtures.
