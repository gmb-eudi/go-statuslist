// Package spec holds the on-the-wire constants of the IETF Token Status List
// (draft-ietf-oauth-status-list-12) that this verifier and any interoperating
// issuer must agree on. It is the single source of truth for the values that
// have drifted across implementations: the CWT claim keys, the COSE typ label,
// and the media types. Framework-free (ADR-0004): no imports.
package spec

// Draft is the pinned Token Status List draft this module targets.
const Draft = "draft-ietf-oauth-status-list-12"

// CWT/JWT claim keys. Sub/Exp/Iat are the RFC 8392 standard CWT claim keys;
// StatusList/TTL are the draft's private CWT claim keys (§5.2 / IANA CWT Claims).
const (
	ClaimSub        int64 = 2
	ClaimExp        int64 = 4
	ClaimIat        int64 = 6
	ClaimStatusList int64 = 65533
	ClaimTTL        int64 = 65534
)

// HeaderTyp is the COSE protected-header label carrying the token type (RFC 9596).
const HeaderTyp int64 = 16

// Media types. MediaStatusListJWT is the JOSE `typ` value (a subtype);
// MediaStatusListCWT is the COSE `typ` (label 16) value (the full media type).
const (
	MediaStatusListJWT = "statuslist+jwt"
	MediaStatusListCWT = "application/statuslist+cwt"
)

// Registered status values (draft §7).
const (
	StatusValid     byte = 0x00
	StatusInvalid   byte = 0x01
	StatusSuspended byte = 0x02
)
