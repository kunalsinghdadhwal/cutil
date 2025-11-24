## Overview

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)


cutil is designed for developers who need to manage their own internal PKI infrastructure. It provides both a robust Rust library and a command-line interface for certificate operations, making it suitable for development, testing, and production environments.

## Features

- **Certificate Authority Management**
  - Generate self-signed root certificate authorities
  - Create intermediate CAs with full chain validation
  - Support for multiple signature algorithms (Ed25519, ECDSA P-256/P-384, RSA 2048/3072/4096)
  - Persistent storage with PEM format support

- **Certificate Issuance**
  - Issue TLS server certificates with Subject Alternative Names (SANs)
  - Issue client authentication certificates
  - Dual-purpose certificates for both server and client authentication
  - Custom validity periods and Distinguished Names
  - Proper X.509 v3 extensions (key usage, extended key usage, basic constraints)
  - CRL distribution points and OCSP responder URLs

- **Certificate Revocation**
  - Track revoked certificates with reason codes
  - Generate Certificate Revocation Lists (CRLs) compliant with RFC 5280
  - Support for all standard revocation reasons

- **Remote Certificate Inspection**
  - Fetch and parse certificate chains from any TLS server
  - Extract detailed certificate information
  - Support for both human-readable and JSON output formats
  - Verify certificate chain validity

- **Export Formats**
  - PEM encoded certificates and private keys
  - PKCS#12/PFX archives with password protection
  - Full certificate chains
  - DER encoding support

## Installation

Add CUtil to your `Cargo.toml`:

```toml
[dependencies]
cutil = "0.1"
```

## Quick Start

### Library Usage

```rust
use cutil::ca::CertificateAuthority;
use cutil::cert::CertificateBuilder;
use cutil::types::{CertSigAlgo, DistinguishedName};
use cutil::error::Result;

fn main() -> Result<()> {
    // Create a root CA
    let subject = DistinguishedName::new("Example Root CA")
        .with_organization("Example Corp")
        .with_country("US");

    let ca = CertificateAuthority::new_root(
        subject,
        CertSigAlgo::EcdsaP256,
        3650, // 10 years
    )?;
    
    ca.save_pem("ca.pem", "ca-key.pem")?;

    // Issue a server certificate
    let mut loaded_ca = CertificateAuthority::load_pem(
        "ca.pem",
        "ca-key.pem",
        CertSigAlgo::EcdsaP256,
    )?;

    let cert = CertificateBuilder::server("example.com")
        .with_dns_san("www.example.com")
        .with_dns_san("api.example.com")
        .with_validity_days(365)
        .issue(&mut loaded_ca)?;

    cert.save_pem("server.pem", "server-key.pem")?;
    
    Ok(())
}
```

### Command-Line Interface

```bash
# Initialize a root CA
cutil init --cn "My Root CA" --org "My Company" --country US

# Issue a server certificate
cutil cert --cn example.com --dns example.com,www.example.com --validity 365

# Fetch remote certificate chain
cutil fetch google.com:443 --format pretty
```

## Library API Reference

### Certificate Authority Operations

#### Creating a Root CA

```rust
use cutil::ca::CertificateAuthority;
use cutil::types::{CertSigAlgo, DistinguishedName};
use cutil::error::Result;

fn create_root_ca() -> Result<CertificateAuthority> {
    let subject = DistinguishedName::new("Example Root CA")
        .with_organization("Example Corporation")
        .with_organizational_unit("Security")
        .with_country("US")
        .with_state("California")
        .with_locality("San Francisco");

    let ca = CertificateAuthority::new_root(
        subject,
        CertSigAlgo::EcdsaP256,
        3650, // Validity in days
    )?;

    ca.save_pem("root-ca.pem", "root-ca-key.pem")?;
    Ok(ca)
}
```

#### Creating an Intermediate CA

```rust
use cutil::ca::CertificateAuthority;
use cutil::types::{CertSigAlgo, DistinguishedName};
use cutil::error::Result;

fn create_intermediate_ca() -> Result<CertificateAuthority> {
    // Load the parent (root) CA
    let parent_ca = CertificateAuthority::load_pem(
        "root-ca.pem",
        "root-ca-key.pem",
        CertSigAlgo::EcdsaP256,
    )?;

    // Create intermediate CA subject
    let subject = DistinguishedName::new("Example Intermediate CA")
        .with_organization("Example Corporation")
        .with_organizational_unit("Security");

    // Create the intermediate CA
    let intermediate_ca = CertificateAuthority::new_intermediate(
        subject,
        CertSigAlgo::EcdsaP256,
        1825, // 5 years
        &parent_ca,
    )?;

    intermediate_ca.save_pem("intermediate-ca.pem", "intermediate-ca-key.pem")?;
    Ok(intermediate_ca)
}
```

#### Loading an Existing CA

```rust
use cutil::ca::CertificateAuthority;
use cutil::types::CertSigAlgo;
use cutil::error::Result;

fn load_ca() -> Result<CertificateAuthority> {
    let ca = CertificateAuthority::load_pem(
        "ca.pem",
        "ca-key.pem",
        CertSigAlgo::EcdsaP256,
    )?;
    Ok(ca)
}
```

### Certificate Issuance

#### Server Certificates

```rust
use cutil::cert::CertificateBuilder;
use cutil::types::{CertSigAlgo, DistinguishedName};
use cutil::ca::CertificateAuthority;
use cutil::error::Result;

fn issue_server_certificate(ca: &mut CertificateAuthority) -> Result<()> {
    let cert = CertificateBuilder::server("example.com")
        .with_dns_san("example.com")
        .with_dns_san("www.example.com")
        .with_dns_san("api.example.com")
        .with_dns_san("*.internal.example.com")
        .with_validity_days(365)
        .with_algorithm(CertSigAlgo::EcdsaP256)
        .issue(ca)?;

    cert.save_pem("server.pem", "server-key.pem")?;
    Ok(())
}
```

#### Server Certificates with Custom Subject

```rust
use cutil::cert::CertificateBuilder;
use cutil::types::{CertType, DistinguishedName};
use cutil::ca::CertificateAuthority;
use cutil::error::Result;

fn issue_server_with_custom_subject(ca: &mut CertificateAuthority) -> Result<()> {
    let subject = DistinguishedName::new("example.com")
        .with_organization("Example Corporation")
        .with_organizational_unit("Web Services")
        .with_locality("San Francisco")
        .with_state("California")
        .with_country("US");

    let cert = CertificateBuilder::new("example.com".to_string(), CertType::Server)
        .with_subject(subject)
        .with_dns_san("example.com")
        .with_dns_san("www.example.com")
        .with_validity_days(365)
        .issue(ca)?;

    cert.save_pem("server.pem", "server-key.pem")?;
    Ok(())
}
```

#### Client Certificates

```rust
use cutil::cert::CertificateBuilder;
use cutil::ca::CertificateAuthority;
use cutil::error::Result;

fn issue_client_certificate(ca: &mut CertificateAuthority) -> Result<()> {
    let cert = CertificateBuilder::client("user@example.com")
        .with_email_san("user@example.com")
        .with_validity_days(365)
        .issue(ca)?;

    cert.save_pem("client.pem", "client-key.pem")?;
    Ok(())
}
```

#### Certificates with IP SANs

```rust
use cutil::cert::CertificateBuilder;
use cutil::ca::CertificateAuthority;
use cutil::error::Result;
use std::net::IpAddr;

fn issue_certificate_with_ip_sans(ca: &mut CertificateAuthority) -> Result<()> {
    let cert = CertificateBuilder::server("internal-service")
        .with_dns_san("internal-service.local")
        .with_ip_san("192.168.1.100".parse::<IpAddr>().unwrap())
        .with_ip_san("10.0.0.50".parse::<IpAddr>().unwrap())
        .with_validity_days(365)
        .issue(ca)?;

    cert.save_pem("internal-service.pem", "internal-service-key.pem")?;
    Ok(())
}
```

#### Certificates with CRL and OCSP URLs

```rust
use cutil::cert::CertificateBuilder;
use cutil::ca::CertificateAuthority;
use cutil::error::Result;

fn issue_certificate_with_revocation_urls(ca: &mut CertificateAuthority) -> Result<()> {
    let cert = CertificateBuilder::server("example.com")
        .with_dns_san("example.com")
        .with_crl_distribution_point("http://crl.example.com/ca.crl")
        .with_ocsp_server("http://ocsp.example.com")
        .with_validity_days(365)
        .issue(ca)?;

    cert.save_pem("server.pem", "server-key.pem")?;
    Ok(())
}
```

### Certificate Export Formats

#### Exporting Certificate Chains

```rust
use cutil::ca::{CertificateAuthority, IssuedCertificate};
use cutil::error::Result;

fn export_certificate_chain(cert: &IssuedCertificate) -> Result<()> {
    // Save full certificate chain (cert + CA chain)
    cert.save_chain("fullchain.pem")?;
    Ok(())
}
```

#### Exporting as PKCS#12

```rust
use cutil::ca::IssuedCertificate;
use cutil::error::Result;

fn export_pkcs12(cert: &IssuedCertificate) -> Result<()> {
    let p12_data = cert.export_pkcs12(
        "secure_password_123",
        "My Server Certificate",
    )?;
    
    std::fs::write("certificate.p12", p12_data)?;
    Ok(())
}
```

### Certificate Revocation

#### Revoking a Certificate

```rust
use cutil::ca::CertificateAuthority;
use cutil::types::RevocationReason;
use cutil::error::Result;

fn revoke_certificate(ca: &mut CertificateAuthority, serial: Vec<u8>) -> Result<()> {
    ca.revoke_certificate(serial, RevocationReason::KeyCompromise)?;
    Ok(())
}
```

#### Generating a Certificate Revocation List (CRL)

```rust
use cutil::ca::CertificateAuthority;
use cutil::error::Result;

fn generate_crl(ca: &CertificateAuthority) -> Result<()> {
    let crl_pem = ca.generate_crl()?;
    std::fs::write("ca.crl", crl_pem)?;
    
    println!("CRL generated with {} revoked certificates", 
             ca.revoked_certificates().len());
    Ok(())
}
```

#### Checking Revoked Certificates

```rust
use cutil::ca::CertificateAuthority;
use cutil::error::Result;

fn list_revoked_certificates(ca: &CertificateAuthority) -> Result<()> {
    for revoked in ca.revoked_certificates() {
        println!("Serial: {:?}", revoked.serial_number);
        println!("Revocation Date: {}", revoked.revocation_date);
        println!("Reason: {:?}", revoked.reason);
        println!("---");
    }
    Ok(())
}
```

### Remote Certificate Inspection

#### Fetching Certificate Chains

```rust
use cutil::fetch::fetch_certificate_chain;
use cutil::error::Result;

fn fetch_remote_chain() -> Result<()> {
    let chain = fetch_certificate_chain("google.com", 443)?;
    
    println!("Server: {}", chain.server);
    println!("Number of certificates: {}", chain.certificates.len());
    
    for (i, cert) in chain.certificates.iter().enumerate() {
        println!("\nCertificate {}:", i);
        println!("  Subject: {}", cert.subject);
        println!("  Issuer: {}", cert.issuer);
        println!("  Valid from: {}", cert.not_before);
        println!("  Valid until: {}", cert.not_after);
        println!("  Is CA: {}", cert.is_ca);
    }
    
    Ok(())
}
```

#### Displaying Certificate Chain Information

```rust
use cutil::fetch::{fetch_certificate_chain, display_certificate_chain, OutputFormat};
use cutil::error::Result;

fn display_remote_chain_pretty() -> Result<()> {
    let chain = fetch_certificate_chain("github.com", 443)?;
    let output = display_certificate_chain(&chain, OutputFormat::Pretty)?;
    println!("{}", output);
    Ok(())
}

fn display_remote_chain_json() -> Result<()> {
    let chain = fetch_certificate_chain("github.com", 443)?;
    let output = display_certificate_chain(&chain, OutputFormat::Json)?;
    println!("{}", output);
    Ok(())
}
```

#### Saving Certificate Chain to File

```rust
use cutil::fetch::{fetch_certificate_chain, display_certificate_chain, OutputFormat};
use cutil::error::Result;

fn save_chain_info(host: &str, port: u16, output_file: &str) -> Result<()> {
    let chain = fetch_certificate_chain(host, port)?;
    let output = display_certificate_chain(&chain, OutputFormat::Json)?;
    std::fs::write(output_file, output)?;
    Ok(())
}
```

## Signature Algorithms

CUtil supports multiple signature algorithms with varying security levels and performance characteristics:

### Ed25519 (Recommended for Modern Systems)

```rust
use cutil::types::CertSigAlgo;

let algorithm = CertSigAlgo::Ed25519;
```

- Modern elliptic curve signature algorithm
- Fast signing and verification
- Compact signatures and keys
- High security level

### ECDSA with NIST Curves

```rust
use cutil::types::CertSigAlgo;

// P-256 (secp256r1) - Good balance of security and performance
let p256 = CertSigAlgo::EcdsaP256;

// P-384 (secp384r1) - Higher security level
let p384 = CertSigAlgo::EcdsaP384;
```

### RSA

```rust
use cutil::types::CertSigAlgo;

let rsa2048 = CertSigAlgo::Rsa2048; // Minimum recommended
let rsa3072 = CertSigAlgo::Rsa3072; // Good for long-term security
let rsa4096 = CertSigAlgo::Rsa4096; // Maximum security
```

### Algorithm Selection Guide

- **Ed25519**: Best choice for new deployments (fast, secure, modern)
- **ECDSA P-256**: Good compatibility, widely supported
- **ECDSA P-384**: Higher security requirements
- **RSA 2048**: Legacy compatibility (minimum acceptable)
- **RSA 3072/4096**: Long-term security, regulatory compliance

## Distinguished Names

### Creating Distinguished Names

```rust
use cutil::types::DistinguishedName;

let dn = DistinguishedName::new("example.com")
    .with_organization("Example Corporation")
    .with_organizational_unit("IT Department")
    .with_country("US")
    .with_state("California")
    .with_locality("San Francisco");
```

### Available Fields

- **Common Name (CN)**: Primary identifier (required)
- **Organization (O)**: Company or organization name
- **Organizational Unit (OU)**: Department or division
- **Country (C)**: Two-letter country code (ISO 3166-1 alpha-2)
- **State (ST)**: State or province
- **Locality (L)**: City or locality

## Revocation Reasons

```rust
use cutil::types::RevocationReason;

let reasons = [
    RevocationReason::Unspecified,
    RevocationReason::KeyCompromise,
    RevocationReason::CACompromise,
    RevocationReason::AffiliationChanged,
    RevocationReason::Superseded,
    RevocationReason::CessationOfOperation,
];
```

## Error Handling

CUtil uses a custom `Result` type for comprehensive error handling:

```rust
use cutil::error::{Result, Error};

fn handle_errors() -> Result<()> {
    match some_operation() {
        Ok(value) => {
            println!("Success: {:?}", value);
            Ok(())
        }
        Err(Error::IoError(e)) => {
            eprintln!("I/O error: {}", e);
            Err(Error::IoError(e))
        }
        Err(Error::CertificateGeneration(msg)) => {
            eprintln!("Certificate generation failed: {}", msg);
            Err(Error::CertificateGeneration(msg))
        }
        Err(e) => {
            eprintln!("Other error: {}", e);
            Err(e)
        }
    }
}
```

## Command-Line Interface

The CUtil CLI provides a complete command-line interface for all PKI operations.

### Initialize a Root CA

```bash
cutil init \
    --cn "Example Root CA" \
    --org "Example Corporation" \
    --ou "Security" \
    --country US \
    --state California \
    --locality "San Francisco" \
    --algorithm ecdsa-p256 \
    --validity 3650 \
    --cert-out root-ca.pem \
    --key-out root-ca-key.pem
```

### Create an Intermediate CA

```bash
cutil init \
    --cn "Example Intermediate CA" \
    --org "Example Corporation" \
    --algorithm ecdsa-p256 \
    --validity 1825 \
    --intermediate \
    --parent-cert root-ca.pem \
    --parent-key root-ca-key.pem \
    --cert-out intermediate-ca.pem \
    --key-out intermediate-ca-key.pem
```

### Issue a Server Certificate

```bash
cutil cert \
    --cn example.com \
    --cert-type server \
    --dns example.com \
    --dns www.example.com \
    --dns api.example.com \
    --org "Example Corporation" \
    --validity 365 \
    --ca-cert ca.pem \
    --ca-key ca-key.pem \
    --cert-out server.pem \
    --key-out server-key.pem \
    --chain-out fullchain.pem
```

### Issue a Client Certificate

```bash
cutil cert \
    --cn "John Doe" \
    --cert-type client \
    --email john.doe@example.com \
    --org "Example Corporation" \
    --validity 365 \
    --ca-cert ca.pem \
    --ca-key ca-key.pem \
    --cert-out client.pem \
    --key-out client-key.pem
```

### Export Certificate as PKCS#12

```bash
cutil cert \
    --cn example.com \
    --cert-type server \
    --dns example.com \
    --ca-cert ca.pem \
    --ca-key ca-key.pem \
    --cert-out server.pem \
    --key-out server-key.pem \
    --p12-out server.p12 \
    --p12-password "secure_password"
```

### Fetch Remote Certificate Chain

```bash
# Pretty formatted output
cutil fetch google.com:443

# JSON output
cutil fetch github.com:443 --format json

# Save to file
cutil fetch example.com:443 --format json --output example-chain.json
```

### Revoke a Certificate

```bash
cutil revoke \
    --serial 01:02:03:04:05:06:07:08 \
    --reason key-compromise \
    --ca-cert ca.pem \
    --ca-key ca-key.pem
```

Available revocation reasons:
- `unspecified`
- `key-compromise` or `keycompromise`
- `ca-compromise` or `cacompromise`
- `affiliation-changed` or `affiliationchanged`
- `superseded`
- `cessation` or `cessationofoperation`

### Generate Certificate Revocation List

```bash
cutil crl \
    --ca-cert ca.pem \
    --ca-key ca-key.pem \
    --output ca.crl
```

### Display Certificate Chain

```bash
cutil chain server.pem
```

## Best Practices
### Development and Testing

```rust
use cutil::ca::CertificateAuthority;
use cutil::cert::CertificateBuilder;
use cutil::types::{CertSigAlgo, DistinguishedName};
use cutil::error::Result;

fn create_test_pki() -> Result<()> {
    // Create test CA
    let ca_subject = DistinguishedName::new("Test CA");
    let mut ca = CertificateAuthority::new_root(
        ca_subject,
        CertSigAlgo::EcdsaP256,
        365,
    )?;

    // Issue test certificate
    let cert = CertificateBuilder::server("localhost")
        .with_dns_san("localhost")
        .with_ip_san("127.0.0.1".parse().unwrap())
        .with_validity_days(30)
        .issue(&mut ca)?;

    cert.save_pem("test-cert.pem", "test-key.pem")?;
    Ok(())
}
```

## Examples

Complete working examples are available in the repository:

- **basic_ca.rs**: Create a CA and issue server/client certificates
- **fetch_remote.rs**: Fetch and inspect remote TLS certificates

Run examples with:

```bash
cargo run --example basic_ca
cargo run --example fetch_remote
```

## Dependencies

CUtil is built on industry-standard cryptographic libraries:

- **rcgen**: Certificate generation and signing
- **rustls**: TLS protocol implementation
- **rustls-pemfile**: PEM file parsing
- **webpki**: Web PKI certificate validation
- **x509-parser**: X.509 certificate parsing
- **thiserror**: Ergonomic error handling
- **chrono**: Date and time operations
- **colored**: Terminal output formatting
- **serde** / **serde_json**: JSON serialization support
- **clap**: Command-line argument parsing
- **p12**: PKCS#12 archive support
