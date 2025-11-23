# CertUtil

A complete internal PKI (Public Key Infrastructure) toolkit for Rust that provides certificate authority management, certificate issuance, and remote certificate inspection.

## Features

- **Certificate Authority Management**
  - Generate self-signed root CAs
  - Create intermediate CAs
  - Support for multiple signature algorithms (Ed25519, ECDSA P-256/P-384, RSA 2048/3072/4096)
  - Save and load CA certificates and keys

- **Certificate Issuance**
  - Issue server certificates with Subject Alternative Names (SANs)
  - Issue client certificates with email addresses
  - Custom validity periods and Distinguished Names
  - Proper key usage and extended key usage extensions
  - CRL distribution points and OCSP URLs

- **Certificate Revocation**
  - Track revoked certificates
  - Generate Certificate Revocation Lists (CRLs)
  - Multiple revocation reasons supported

- **Remote Certificate Inspection**
  - Fetch certificate chains from any TLS server
  - Parse and display certificate details
  - Pretty-printed colored output or JSON format
  - Extract validity, SANs, key usage, and more

- **Export Formats**
  - PEM (certificates and keys)
  - PKCS#12/PFX (with password protection)
  - Certificate chains

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
certutil = "0.1"
```

For CLI support:

```toml
[dependencies]
certutil = { version = "0.1", features = ["cli"] }
```

For JSON output:

```toml
[dependencies]
certutil = { version = "0.1", features = ["json"] }
```

## Usage

### Library Usage

#### Create a Root CA

```rust
use certutil::ca::CertificateAuthority;
use certutil::types::{CertSigAlgo, DistinguishedName};

let subject = DistinguishedName::new("My Root CA")
    .with_organization("My Company")
    .with_country("US");

let ca = CertificateAuthority::new_root(
    subject,
    CertSigAlgo::EcdsaP256,
    3650, // 10 years
)?;

ca.save_pem("ca.pem", "ca-key.pem")?;
```

#### Issue a Server Certificate

```rust
use certutil::ca::CertificateAuthority;
use certutil::cert::CertificateBuilder;
use certutil::types::CertSigAlgo;

let mut ca = CertificateAuthority::load_pem(
    "ca.pem",
    "ca-key.pem",
    CertSigAlgo::EcdsaP256,
)?;

let cert = CertificateBuilder::server("example.com")
    .with_dns_san("www.example.com")
    .with_dns_san("api.example.com")
    .with_validity_days(365)
    .issue(&mut ca)?;

cert.save_pem("server.pem", "server-key.pem")?;
```

#### Issue a Client Certificate

```rust
use certutil::cert::CertificateBuilder;

let cert = CertificateBuilder::client("user@example.com")
    .with_email_san("user@example.com")
    .with_validity_days(365)
    .issue(&mut ca)?;

cert.save_pem("client.pem", "client-key.pem")?;
```

#### Fetch and Inspect Remote Certificates

```rust
use certutil::fetch::{fetch_certificate_chain, display_certificate_chain, OutputFormat};

let chain = fetch_certificate_chain("example.com", 443)?;
let output = display_certificate_chain(&chain, OutputFormat::Pretty)?;
println!("{}", output);
```

#### Export as PKCS#12

```rust
let p12_data = cert.export_pkcs12("password123", "My Certificate")?;
std::fs::write("certificate.p12", p12_data)?;
```

#### Revoke a Certificate

```rust
use certutil::types::RevocationReason;

ca.revoke_certificate(cert.serial_number, RevocationReason::Superseded)?;
let crl = ca.generate_crl()?;
std::fs::write("ca.crl", crl)?;
```

### CLI Usage

Build the CLI binary:

```bash
cargo build --release --features cli
```

#### Initialize a Root CA

```bash
certutil init \
    --cn "My Root CA" \
    --org "My Company" \
    --country US \
    --algorithm ecdsa-p256 \
    --validity 3650 \
    --cert-out ca.pem \
    --key-out ca-key.pem
```

#### Issue a Server Certificate

```bash
certutil cert \
    --cn example.com \
    --cert-type server \
    --dns example.com,www.example.com,api.example.com \
    --validity 365 \
    --ca-cert ca.pem \
    --ca-key ca-key.pem \
    --cert-out server.pem \
    --key-out server-key.pem \
    --chain-out server-chain.pem
```

#### Fetch Remote Certificate Chain

```bash
certutil fetch google.com:443 --format pretty
certutil fetch github.com:443 --format json --output github-certs.json
```

#### Revoke a Certificate

```bash
certutil revoke \
    --serial 01:02:03:04:05:06:07:08 \
    --reason key-compromise \
    --ca-cert ca.pem \
    --ca-key ca-key.pem
```

#### Generate CRL

```bash
certutil crl \
    --ca-cert ca.pem \
    --ca-key ca-key.pem \
    --output ca.crl
```

## Supported Algorithms

- **Ed25519**: Modern elliptic curve signature algorithm
- **ECDSA P-256**: NIST P-256 curve (secp256r1)
- **ECDSA P-384**: NIST P-384 curve (secp384r1)
- **RSA 2048**: RSA with 2048-bit keys
- **RSA 3072**: RSA with 3072-bit keys
- **RSA 4096**: RSA with 4096-bit keys

## Certificate Types

- **Root CA**: Self-signed certificate authority
- **Intermediate CA**: CA signed by another CA
- **Server**: TLS server authentication certificate
- **Client**: TLS client authentication certificate
- **Both**: Dual-purpose server and client certificate

## Examples

See the `examples/` directory for complete working examples:

- `basic_ca.rs` - Create a CA and issue certificates
- `fetch_remote.rs` - Fetch and inspect remote certificates
- `intermediate_ca.rs` - Create an intermediate CA
- `revocation.rs` - Certificate revocation workflow

## Dependencies

- `rcgen` - Certificate generation
- `rustls` - TLS implementation
- `x509-parser` - X.509 certificate parsing
- `thiserror` - Error handling
- `chrono` - Date and time handling
- `colored` - Terminal output coloring
- `clap` - CLI argument parsing (optional)
- `serde` + `serde_json` - JSON serialization (optional)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.