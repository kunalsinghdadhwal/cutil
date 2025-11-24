# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-11-24

### Added

- Initial release of CUtil PKI toolkit
- Certificate Authority management
  - Create self-signed root CAs
  - Create intermediate CAs
  - Support for multiple signature algorithms (Ed25519, ECDSA P-256/P-384, RSA 2048/3072/4096)
  - Load and save CA certificates and keys in PEM format
- Certificate issuance
  - Issue TLS server certificates
  - Issue client authentication certificates
  - Dual-purpose certificates (server and client)
  - Subject Alternative Names (DNS, IP, Email)
  - Custom validity periods
  - Distinguished Name customization
  - X.509 v3 extensions (key usage, extended key usage, basic constraints)
  - CRL distribution points and OCSP responder URLs
- Certificate revocation
  - Track revoked certificates with reason codes
  - Generate Certificate Revocation Lists (CRLs)
  - Support for all standard revocation reasons
- Remote certificate inspection
  - Fetch certificate chains from TLS servers
  - Parse and display certificate information
  - Pretty-printed colored output
  - JSON output format
- Export formats
  - PEM encoding for certificates and keys
  - PKCS#12/PFX archives with password protection
  - Full certificate chain export
- Command-line interface
  - Initialize root and intermediate CAs
  - Issue server and client certificates
  - Fetch and inspect remote certificates
  - Revoke certificates
  - Generate CRLs
  - Display certificate chains
- Comprehensive API
  - `CertificateAuthority` for CA management
  - `CertificateBuilder` for certificate issuance
  - `fetch_certificate_chain` for remote inspection
  - Error handling with custom `Result` and `Error` types
- Documentation
  - Comprehensive README with examples
  - API documentation
  - CLI usage examples

### Changed

- N/A (initial release)

### Deprecated

- N/A (initial release)

### Removed

- N/A (initial release)

### Fixed

- N/A (initial release)

### Security

- Secure key generation using industry-standard algorithms
- Private key protection in PEM format
- PKCS#12 archives with password encryption

[Unreleased]: https://github.com/kunalsinghdadhwal/cutil/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kunalsinghdadhwal/cutil/releases/tag/v0.1.0