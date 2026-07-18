# Pinned specification versions

| Spec | Version pinned |
|---|---|
| IETF Token Status List | draft-ietf-oauth-status-list-21 |
| JWS | RFC 7515 (via go-eudi-crypto) |
| COSE_Sign1 / CWT | RFC 9052 / RFC 8392 (via go-eudi-crypto) — **Sign1 only, COSE_Mac0 not supported, see Open Items** |
| zlib / DEFLATE | RFC 1950 / RFC 1951 |
| ARF Topic 7 revocation | ARF 2.9 §6.6.3.7; annex-2.02 HLRs VCR_01, VCR_11, VCR_12, VCR_13 |
| Short-lived exemption origin | ETSI EN 319 411-1 v1.4.1 REV-6.2.4-03A (24h) |

Both `references/statuslist-draft12.txt` and `references/statuslist-draft21.txt` are vendored.
draft-21 is the pinned/authoritative version; draft-12 is kept for historical reference since it
was the version this library was originally built and reviewed against. A full section-by-section
diff of -12 → -21 (2026-07-06) found no wire-breaking changes to anything this library implements
— see the Open Items below for the two substantive deltas (`exp`/`ttl` recommendation strength,
the new COSE_Mac0 option) and the one narrowed registry range (`0x0B`).

## Open items (flagged to maintainers)
- The CWT/JWT claim keys used in `cwt.go`/`token.go`/`spec/spec.go` — the JWT
  standard claims (`sub`, `iat`=6, `exp`=4) and the CBOR equivalents
  (`sub`=2, `iat`=6, `exp`=4), plus the two private claim keys
  (`status_list`=65533, `ttl`=65534), the CWT `typ` label (16) and both media
  type strings (`statuslist+jwt` / `application/statuslist+cwt`) — are
  **confirmed directly against the vendored primary source**, originally
  `references/statuslist-draft12.txt` §5.1/§5.2/§14, re-confirmed unchanged in
  `references/statuslist-draft21.txt` §5.1/§5.2/§14 (2026-07-06 diff pass). The
  earlier EU Statium reference-verifier cross-check
  (`references/eu-statuslist/eudi-lib-kmp-statium-main`,
  `references/eu-statuslist/eudi-lib-ios-statium-swift-main`) independently
  agrees. The draft-12 comparison also found and fixed a `sub`/`iat`
  required-claims gap: §5.1/§5.2 mark both REQUIRED and §8.3 step 3.2 makes
  checking for their existence a normative Relying Party step, but the decoder
  previously accepted a token missing either (`iat==0`/`sub==""` decoded to the
  Go zero value and was silently tolerated). `decodeClaims` (`token.go`) now
  rejects both with `ErrMalformed` — see the "iat/sub required-claim" fix
  (`.superpowers/sdd/task-iat-sub-required-brief.md`). Note: draft-21 §5.1/§5.2
  softened `exp`/`ttl` from OPTIONAL to RECOMMENDED (draft-13) — no code change
  needed, both remain legitimately absent-tolerant (`applyFreshness`/`cacheTTL`
  already treat `exp==0`/`ttl==0` as "not provided", never as an error).
- **COSE_Mac0 not supported (tracked limitation, draft-21 §5.2/§11.6).**
  draft-15 added a second allowed CWT protection mechanism: "The COSE message
  MUST either be the tagged COSE_Sign1_Tagged (18) or **COSE_Mac0_Tagged (17)**"
  (RFC 9052 §2). `checkTokenStatusList`/`verifyToken` (`token.go`) and
  `go-eudi-crypto`'s `VerifyCOSESign1` only implement the Sign1 path; there is no
  COSE_Mac0 verification anywhere in this library or in `go-eudi-crypto`, and the
  underlying `github.com/veraison/go-cose@v1.3.0` has no `Mac0Message` type at
  all (would need a library upgrade or a hand-rolled RFC 9052 §6.2 MAC
  implementation to add). A Mac0-protected Status List Token fails closed
  today — `cose.Sign1Message.UnmarshalCBOR` rejects a tag-17 message as
  malformed (`ErrMalformed`, fuzzed via `FuzzVerifyCOSESign1` in
  `go-eudi-crypto`, no panic) — but such a token cannot be verified at all, not
  even correctly. **Deferred, not urgent:** draft-21 §11.6 itself says MAC-based
  tokens are for narrow issuer=RP trust deployments with an out-of-band shared
  key, expects most deployments to use signatures, and tells implementers to
  "default to digital signatures if unsure" — not the EU multi-issuer/
  multi-verifier ecosystem this library serves. No known real issuer (EU
  reference `eudi-srv-statuslist-py`, our own `status-list-go`) emits Mac0.
  Revisit if that changes. Implementing it would touch `go-eudi-crypto` first
  (framework-free COSE layer, hard rule 4), then dispatch logic here.
- The Attestation Revocation List ("Identifier List") wire format is **confirmed
  absent** from both vendored drafts: no mention of "identifier list",
  "attestation revocation" or "ARL" appears anywhere in `statuslist-draft12.txt`
  (~4000 lines) or `statuslist-draft21.txt` (~4500 lines). This mechanism has no
  IETF basis at all, in any revision checked — it is purely an
  ARF invention, and its wire format is still governed solely by the un-vendored
  Commission TS referenced by ARF VCR_11. The JSON/CBOR shape in `identifier.go`
  is therefore a documented synthetic choice (ADR-0007 governs the OSS packaging
  / synthetic test-vector approach, not the wire format itself), and its
  `iat`/`sub` semantics are NOT governed by draft-12 — the required-claims fix
  above deliberately does not touch `decodeIdentifierList` / `tokenMeta`. The
  mechanism therefore stays **experimental**: this library only hardens it to
  fail closed on an unrecognized shape (missing `identifier_list.ids`); it must
  be verified against the VCR_11 TS before v1.
- Status Types `0x03` and a range are registered in the draft (§7.1 Status
  Types Values; §14.5.2 initial registry contents) as `APPLICATION_SPECIFIC`,
  and all other Status Type values are "reserved for future registration".
  **Range corrected for draft-21: `0x0C`–`0x0F`** (draft-12 had `0x0B`–`0x0F`;
  draft-14's changelog explicitly notes "removed 0x0B from application-specific
  Status Type" — `0x0B` is now just "reserved for future", not a newly-assigned
  named status). The conclusion is unaffected by the narrowing either way:
  `mapStatus`'s (`status.go`) default-to-`StatusUnknown` for any value besides
  `0x00`/`0x01`/`0x02` covers both the application-specific range and the
  reserved-for-future range identically, so this remains spec-correct
  behaviour, not an approximation.
- ARF citation fix: the "a Relying Party that verifies revocation SHALL support
  BOTH the Attestation Status List and Attestation Revocation List mechanisms"
  requirement is **VCR_12**, not VCR_02 (VCR_02 concerns which revocation
  method a non-qualified-EAA Rulebook must mandate, not the RP-side "support
  both" requirement). Confirmed in
  `references/eudi-doc-architecture-and-reference-framework-main/docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md`.
- All test vectors are generated by an in-test issuer (ADR-0007). Replace with
  draft appendix vectors if the vendored draft ships them.
