package statuslist

import "errors"

// Sentinel errors. Framework-free: callers (eudi-verifier-core) map
// these to problem codes — a StatusRevoked/StatusSuspended verdict to
// err:revocation:revoked (suspended=true detail), an
// inconclusive result to err:revocation:unavailable. None carry attribute
// values; they may carry list URIs, indices and kids.
var (
	ErrUnsupported      = errors.New("statuslist: unsupported reference kind or token format")
	ErrFetch            = errors.New("statuslist: status list could not be fetched")
	ErrKeyUnresolved    = errors.New("statuslist: issuer key could not be resolved")
	ErrVerify           = errors.New("statuslist: status list token signature verification failed")
	ErrMalformed        = errors.New("statuslist: malformed status list token")
	ErrSubMismatch      = errors.New("statuslist: token sub does not equal the referenced list URI")
	ErrUnknownBitWidth  = errors.New("statuslist: status list bits must be 1, 2, 4 or 8")
	ErrIndexOutOfRange  = errors.New("statuslist: status index out of range for the list")
	ErrDecompress       = errors.New("statuslist: status list decompression failed")
	ErrDecompressTooBig = errors.New("statuslist: decompressed status list exceeds size cap")
	ErrExpired          = errors.New("statuslist: status list token expired beyond MaxStale")
	// ErrWrongType is returned when a Status List Token's `typ` (JOSE header /
	// COSE label 16) is absent or not the expected status-list media type
	// ([Token Status List §5.1/§5.2]). Fail closed.
	ErrWrongType = errors.New("statuslist: wrong or missing typ")
	// ErrIssuedInFuture is returned when a token's iat is later than now+ClockSkew
	// ([Token Status List §5] / RFC 8392 iat). Fail closed.
	ErrIssuedInFuture = errors.New("statuslist: token issued in the future")
)
