// Package statuslist implements EUDI credential revocation checking: the IETF
// Token Status List mechanism (draft-ietf-oauth-status-list) in JWT and CWT
// form, and the ARF Attestation Revocation List ("Identifier List") mechanism
// (ARF 2.9 Topic 7). It is framework-free: Fetcher, Cache and the
// clock are injected, all JOSE/COSE verification goes through go-eudi-crypto,
// and no attribute values ever appear in errors or provenance.
package statuslist
