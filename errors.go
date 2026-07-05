package statuslist

import "errors"

// Sentinel errors. Framework-free (ADR-0004): callers (verifier-core) map
// these to problem codes — a StatusRevoked/StatusSuspended verdict to
// err:revocation:revoked (suspended=true detail per the WP-04 Decisions), an
// inconclusive result to err:revocation:unavailable. None carry attribute
// values (hard rule 3); they may carry list URIs, indices and kids.
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
)
