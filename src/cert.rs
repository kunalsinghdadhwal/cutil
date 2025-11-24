use crate::ca::{CertificateAuthority, IssuedCertificate};
use crate::error::Result;
use crate::types::{CertSigAlgo, CertType, CertificateRequest, DistinguishedName};
use std::net::IpAddr;

pub struct CertificateBuilder {
    request: CertificateRequest,
    algorithm: CertSigAlgo,
}

impl CertificateBuilder {
    pub fn new(common_name: impl Into<String>, cert_type: CertType) -> Self {
        Self {
            request: CertificateRequest::new(common_name, cert_type),
            algorithm: CertSigAlgo::EcdsaP256,
        }
    }

    pub fn server(common_name: impl Into<String>) -> Self {
        Self::new(common_name, CertType::Server)
    }

    pub fn client(common_name: impl Into<String>) -> Self {
        Self::new(common_name, CertType::Client)
    }

    pub fn with_algorithm(mut self, algorithm: CertSigAlgo) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_subject(mut self, subject: DistinguishedName) -> Self {
        self.request = self.request.with_subject(subject);
        self
    }

    pub fn with_dns_san(mut self, dns: impl Into<String>) -> Self {
        self.request.san = self.request.san.with_dns(dns);
        self
    }

    pub fn with_dns_sans(mut self, dns_names: Vec<String>) -> Self {
        for dns in dns_names {
            self.request.san = self.request.san.with_dns(dns);
        }
        self
    }

    pub fn with_ip_san(mut self, ip: IpAddr) -> Self {
        self.request.san = self.request.san.with_ip(ip);
        self
    }

    pub fn with_email_san(mut self, email: impl Into<String>) -> Self {
        self.request.san = self.request.san.with_email(email);
        self
    }

    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.request = self.request.with_validity_days(days);
        self
    }

    pub fn with_crl_distribution_point(mut self, url: impl Into<String>) -> Self {
        self.request = self.request.with_crl_dp(url);
        self
    }

    pub fn with_ocsp_server(mut self, url: impl Into<String>) -> Self {
        self.request = self.request.with_ocsp(url);
        self
    }

    pub fn issue(self, ca: &mut CertificateAuthority) -> Result<IssuedCertificate> {
        ca.issue_certificate(&self.request, self.algorithm)
    }

    pub fn build(self) -> (CertificateRequest, CertSigAlgo) {
        (self.request, self.algorithm)
    }
}

pub fn issue_server_cert(
    ca: &mut CertificateAuthority,
    common_name: impl Into<String>,
    dns_names: Vec<String>,
    validity_days: u32,
) -> Result<IssuedCertificate> {
    let mut builder = CertificateBuilder::server(common_name).with_validity_days(validity_days);

    for dns in dns_names {
        builder = builder.with_dns_san(dns);
    }

    builder.issue(ca)
}

pub fn issue_client_cert(
    ca: &mut CertificateAuthority,
    common_name: impl Into<String>,
    email: Option<String>,
    validity_days: u32,
) -> Result<IssuedCertificate> {
    let mut builder = CertificateBuilder::client(common_name).with_validity_days(validity_days);

    if let Some(email_addr) = email {
        builder = builder.with_email_san(email_addr);
    }

    builder.issue(ca)
}

pub fn issue_wildcard_cert(
    ca: &mut CertificateAuthority,
    domain: impl Into<String>,
    validity_days: u32,
) -> Result<IssuedCertificate> {
    let domain_str = domain.into();
    let wildcard = format!("*.{}", domain_str);

    CertificateBuilder::server(&wildcard)
        .with_validity_days(validity_days)
        .with_dns_san(wildcard)
        .with_dns_san(domain_str)
        .issue(ca)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CertSigAlgo;

    #[test]
    fn test_certificate_builder() {
        let (request, algo) = CertificateBuilder::server("example.com")
            .with_dns_san("www.example.com")
            .with_dns_san("api.example.com")
            .with_validity_days(90)
            .with_algorithm(CertSigAlgo::Ed25519)
            .build();

        assert_eq!(request.subject.common_name, "example.com");
        assert_eq!(request.san.dns_names.len(), 2);
        assert_eq!(request.validity_days, 90);
        assert_eq!(algo, CertSigAlgo::Ed25519);
    }
}
