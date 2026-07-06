package statuslist

import "time"

// Status is the resolved revocation status of a referenced credential. The
// first four values map to Token Status List §7 status types; a fetched list
// entry only ever produces one of them.
type Status int

// Status values. The first four map to Token Status List §7 status types.
const (
	StatusValid     Status = iota // Token Status List §7: 0x00 VALID
	StatusRevoked                 // Token Status List §7: 0x01 INVALID
	StatusSuspended               // Token Status List §7: 0x02 SUSPENDED
	StatusUnknown                 // status type unrecognised, or status not determinable under policy

	// StatusSkippedShortLived is NOT a Token Status List value: Check returns
	// it when the ARF Topic 7 VCR_01 <24h validity exemption legitimately
	// skips the check. It is mirrored in Provenance.Outcome
	// (OutcomeSkippedShortLived) so it appears verbatim in the verification
	// report. Grouped separately from the four real status values on purpose.
	StatusSkippedShortLived
)

func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusRevoked:
		return "revoked"
	case StatusSuspended:
		return "suspended"
	case StatusUnknown:
		return "unknown"
	case StatusSkippedShortLived:
		return "skipped-short-lived"
	default:
		return "invalid"
	}
}

// mapStatus maps a raw Token Status List §7 status type to a Status. Values
// 0x03 and the application-specific range are not revocation verdicts here.
func mapStatus(v int) Status {
	switch v {
	case 0x00:
		return StatusValid
	case 0x01:
		return StatusRevoked
	case 0x02:
		return StatusSuspended
	default:
		return StatusUnknown
	}
}

// Outcome records HOW a status verdict was reached. It is a stable, value-free
// string surfaced verbatim in the verification report (hard rule 7).
type Outcome string

// Outcome values.
const (
	OutcomeChecked           Outcome = "checked"             // list fetched, verified, entry read
	OutcomeCached            Outcome = "checked-cached"      // served from a fresh cache entry
	OutcomeSkippedShortLived Outcome = "skipped-short-lived" // ARF Topic 7 VCR_01 <24h exemption
	OutcomeSkippedFailOpen   Outcome = "skipped-fail-open"   // inconclusive + explicit fail-open flag (AllowFailOpen=true)
	OutcomeUnavailable       Outcome = "unavailable"         // inconclusive + fail-closed ⇒ error
)

// RefKind selects the revocation mechanism. A Relying Party that verifies
// revocation must support both (ARF Topic 7 VCR_12).
type RefKind int

// RefKind values.
const (
	RefTokenStatusList RefKind = iota // IETF Token Status List (ARF "Attestation Status List")
	RefIdentifierList                 // ARF Attestation Revocation List ("Identifier List")
)

// TokenFormat selects the status list token encoding; FormatAuto sniffs.
type TokenFormat int

// TokenFormat values.
const (
	FormatAuto TokenFormat = iota // compact JWS ⇒ JWT, else CWT
	FormatJWT                     // Token Status List §5.1 (statuslist+jwt)
	FormatCWT                     // Token Status List §5.2 (application/statuslist+cwt)
)

// StatusRef identifies the revocation datum to consult. The caller extracts it
// from a credential's status claim: Token Status List §6 status_list{uri, idx}
// for RefTokenStatusList, or the credential identifier + list URI for
// RefIdentifierList.
type StatusRef struct {
	Kind   RefKind
	URI    string      // status list / identifier list URI (status_list.uri)
	Index  int         // token status list entry index (status_list.idx); RefTokenStatusList
	ID     string      // credential identifier; RefIdentifierList
	Format TokenFormat // encoding hint for the fetched token; FormatAuto sniffs
}

// Policy is the per-client revocation policy (hard rule 7). The zero value is
// fail-closed, matching hard rule 7's default; AllowFailOpen is the explicit
// per-client opt-out that is recorded in Provenance and shown in the
// verification report.
type Policy struct {
	AllowFailOpen bool          // false (zero value): inconclusive status ⇒ error; true: ⇒ StatusUnknown, recorded fail-open
	MaxStale      time.Duration // grace beyond a token's exp during which a served list is still accepted (marked Stale)
}

// Provenance records how a verdict was reached; identifiers and outcomes only,
// never attribute values (hard rule 3). Embedded verbatim in the stored
// verification report.
type Provenance struct {
	Mechanism string    // "token-status-list" | "identifier-list"
	URI       string    // list URI consulted (StatusRef.URI)
	Format    string    // "jwt" | "cwt" | ""
	Index     int       // token status list entry index consulted
	ID        string    // identifier consulted (identifier list)
	Bits      int       // status list bit width (token status list)
	Outcome   Outcome   // how the verdict was reached
	FromCache bool      // served from cache
	Stale     bool      // served within the MaxStale grace past the token exp
	FailOpen  bool      // policy allowed proceeding without a conclusive status
	CheckedAt time.Time // clock() at the moment of the check
}

// ShortLivedThreshold is the ARF Topic 7 VCR_01 validity below which a
// revocation check is exempt. The 24h value originates from ETSI EN 319 411-1
// v1.4.1 REV-6.2.4-03A and is not configurable.
const ShortLivedThreshold = 24 * time.Hour

// DefaultMaxDecompressed caps the inflated status list byte array (zip-bomb
// defence, hard rule 5). Overridable via WithMaxDecompressed.
const DefaultMaxDecompressed = 1 << 20 // 1 MiB ⇒ up to ~8.3M single-bit entries
