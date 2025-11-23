//! CertUtil - A complete internal PKI toolkit for Rust
//!
//! This library provides a comprehensive set of tools for managing an internal
//! Public Key Infrastructure (PKI), including:
//!
//! - Generating self-signed root and intermediate Certificate Authorities
//! - Issuing server and client certificates with proper extensions
//! - Revoking certificates and generating Certificate Revocation Lists (CRLs)
//! - Fetching and inspecting remote certificate chains via TLS
//! - Exporting certificates in various formats (PEM, PKCS#12)
//!
//! # Examples
//!
//! ## Creating a Root CA
//!
//! ```no_run
//! use certutil::ca::CertificateAuthority;
//! use certutil::types::{CertSigAlgo, DistinguishedName};
//!
//! let subject = DistinguishedName::new("My Root CA")
//!     .with_organization("My Company")
//!     .with_country("US");
//!
//! let ca = CertificateAuthority::new_root(
//!     subject,
//!     CertSigAlgo::EcdsaP256,
//!     3650, // 10 years
//! ).unwrap();
//!
//! ca.save_pem("ca.pem", "ca-key.pem").unwrap();
//! ```
//!
//! ## Issuing a Server Certificate
//!
//! ```no_run
//! use certutil::ca::CertificateAuthority;
//! use certutil::cert::CertificateBuilder;
//! use certutil::types::CertSigAlgo;
//!
//! let mut ca = CertificateAuthority::load_pem(
//!     "ca.pem",
//!     "ca-key.pem",
//!     CertSigAlgo::EcdsaP256,
//! ).unwrap();
//!
//! let cert = CertificateBuilder::server("example.com")
//!     .with_dns_san("www.example.com")
//!     .with_dns_san("api.example.com")
//!     .with_validity_days(365)
//!     .issue(&mut ca)
//!     .unwrap();
//!
//! cert.save_pem("server.pem", "server-key.pem").unwrap();
//! ```
//!
//! ## Fetching Remote Certificate Chain
//!
//! ```no_run
//! use certutil::fetch::{fetch_certificate_chain, display_certificate_chain, OutputFormat};
//!
//! let chain = fetch_certificate_chain("example.com", 443).unwrap();
//! let output = display_certificate_chain(&chain, OutputFormat::Pretty).unwrap();
//! println!("{}", output);
//! ```

pub mod ca;
pub mod cert;
pub mod error;
pub mod fetch;
pub mod types;

#[cfg(feature = "cli")]
pub mod cli;

pub use error::{Error, Result};

pub use ca::{CertificateAuthority, IssuedCertificate};
pub use cert::CertificateBuilder;
pub use fetch::{fetch_certificate_chain, CertificateChainInfo, ParsedCertificate};
pub use types::{
    CertSigAlgo, CertType, CertificateRequest, DistinguishedName, RevocationReason,
    RevokedCertificate, SubjectAltName,
};

#[cfg(test)]
mod tests {
    use super::*;
    use types::CertSigAlgo;

    #[test]
    fn test_create_root_ca() {
        let subject = DistinguishedName::new("Test Root CA")
            .with_organization("Test Org")
            .with_country("US");

        let ca = CertificateAuthority::new_root(subject, CertSigAlgo::Ed25519, 365);
        assert!(ca.is_ok());
    }

    #[test]
    fn test_issue_server_certificate() {
        let subject = DistinguishedName::new("Test CA");
        let mut ca = CertificateAuthority::new_root(subject, CertSigAlgo::EcdsaP256, 365).unwrap();

        let cert = CertificateBuilder::server("test.example.com")
            .with_dns_san("www.test.example.com")
            .with_validity_days(90)
            .issue(&mut ca);

        assert!(cert.is_ok());
    }

    #[test]
    fn test_issue_client_certificate() {
        let subject = DistinguishedName::new("Test CA");
        let mut ca = CertificateAuthority::new_root(subject, CertSigAlgo::Rsa2048, 365).unwrap();

        let cert = CertificateBuilder::client("user@example.com")
            .with_email_san("user@example.com")
            .with_validity_days(365)
            .issue(&mut ca);

        assert!(cert.is_ok());
    }

    #[test]
    fn test_algorithm_parsing() {
        assert!(matches!(
            "ed25519".parse::<CertSigAlgo>(),
            Ok(CertSigAlgo::Ed25519)
        ));
        assert!(matches!(
            "ecdsa-p256".parse::<CertSigAlgo>(),
            Ok(CertSigAlgo::EcdsaP256)
        ));
        assert!(matches!(
            "rsa4096".parse::<CertSigAlgo>(),
            Ok(CertSigAlgo::Rsa4096)
        ));
    }

    #[test]
    fn test_revocation() {
        let subject = DistinguishedName::new("Test CA");
        let mut ca = CertificateAuthority::new_root(subject, CertSigAlgo::EcdsaP256, 365).unwrap();

        let cert = CertificateBuilder::server("test.example.com")
            .issue(&mut ca)
            .unwrap();

        let result =
            ca.revoke_certificate(cert.serial_number.clone(), RevocationReason::Superseded);
        assert!(result.is_ok());

        let crl = ca.generate_crl();
        assert!(crl.is_ok());
    }
}
