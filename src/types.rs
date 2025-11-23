use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertSigAlgo {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl CertSigAlgo {
    pub fn to_rcgen(&self) -> &rcgen::SignatureAlgorithm {
        match self {
            CertSigAlgo::Ed25519 => &rcgen::PKCS_ED25519,
            CertSigAlgo::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            CertSigAlgo::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            CertSigAlgo::Rsa2048 | CertSigAlgo::Rsa3072 | CertSigAlgo::Rsa4096 => {
                &rcgen::PKCS_RSA_SHA256
            }
        }
    }

    pub fn key_pair(&self) -> Result<rcgen::KeyPair, crate::Error> {
        match self {
            CertSigAlgo::Ed25519 => rcgen::KeyPair::generate(self.to_rcgen())
                .map_err(|e| crate::Error::CertGen(e.to_string())),
            CertSigAlgo::EcdsaP256 => rcgen::KeyPair::generate(self.to_rcgen())
                .map_err(|e| crate::Error::CertGen(e.to_string())),
            CertSigAlgo::EcdsaP384 => rcgen::KeyPair::generate(self.to_rcgen())
                .map_err(|e| crate::Error::CertGen(e.to_string())),
            CertSigAlgo::Rsa2048 => {
                rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
                    .map_err(|e| crate::Error::CertGen(e.to_string()))
            }
            CertSigAlgo::Rsa3072 => {
                rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
                    .map_err(|e| crate::Error::CertGen(e.to_string()))
            }
            CertSigAlgo::Rsa4096 => {
                rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)
                    .map_err(|e| crate::Error::CertGen(e.to_string()))
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            CertSigAlgo::Ed25519 => "Ed25519",
            CertSigAlgo::EcdsaP256 => "ECDSA P-256",
            CertSigAlgo::EcdsaP384 => "ECDSA P-384",
            CertSigAlgo::Rsa2048 => "RSA 2048",
            CertSigAlgo::Rsa3072 => "RSA 3072",
            CertSigAlgo::Rsa4096 => "RSA 4096",
        }
    }
}

impl std::str::FromStr for CertSigAlgo {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(CertSigAlgo::Ed25519),
            "ecdsa-p256" | "ecdsap256" | "p256" => Ok(CertSigAlgo::EcdsaP256),
            "ecdsa-p384" | "ecdsap384" | "p384" => Ok(CertSigAlgo::EcdsaP384),
            "rsa2048" | "rsa-2048" => Ok(CertSigAlgo::Rsa2048),
            "rsa3072" | "rsa-3072" => Ok(CertSigAlgo::Rsa3072),
            "rsa4096" | "rsa-4096" | "rsa" => Ok(CertSigAlgo::Rsa4096),
            _ => Err(crate::Error::UnsupportedAlgorithm(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    RootCA,
    IntermediateCA,
    Server,
    Client,
    Both,
}

#[derive(Debug, Clone)]
pub struct DistinguishedName {
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
}

impl DistinguishedName {
    pub fn new(cn: impl Into<String>) -> Self {
        Self {
            common_name: cn.into(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        }
    }

    pub fn with_organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    pub fn with_organizational_unit(mut self, ou: impl Into<String>) -> Self {
        self.organizational_unit = Some(ou.into());
        self
    }

    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn with_locality(mut self, locality: impl Into<String>) -> Self {
        self.locality = Some(locality.into());
        self
    }

    pub fn to_rcgen(&self) -> rcgen::DistinguishedName {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, &self.common_name);

        if let Some(ref org) = self.organization {
            dn.push(rcgen::DnType::OrganizationName, org);
        }
        if let Some(ref ou) = self.organizational_unit {
            dn.push(rcgen::DnType::OrganizationalUnitName, ou);
        }
        if let Some(ref country) = self.country {
            dn.push(rcgen::DnType::CountryName, country);
        }
        if let Some(ref state) = self.state {
            dn.push(rcgen::DnType::StateOrProvinceName, state);
        }
        if let Some(ref locality) = self.locality {
            dn.push(rcgen::DnType::LocalityName, locality);
        }

        dn
    }
}

#[derive(Debug, Clone)]
pub struct SubjectAltName {
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub email_addresses: Vec<String>,
}

impl SubjectAltName {
    pub fn new() -> Self {
        Self {
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            email_addresses: Vec::new(),
        }
    }

    pub fn with_dns(mut self, dns: impl Into<String>) -> Self {
        self.dns_names.push(dns.into());
        self
    }

    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip_addresses.push(ip);
        self
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email_addresses.push(email.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.dns_names.is_empty() && self.ip_addresses.is_empty() && self.email_addresses.is_empty()
    }
}

impl Default for SubjectAltName {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub subject: DistinguishedName,
    pub san: SubjectAltName,
    pub cert_type: CertType,
    pub validity_days: u32,
    pub key_usage: Vec<KeyUsage>,
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_servers: Vec<String>,
}

impl CertificateRequest {
    pub fn new(cn: impl Into<String>, cert_type: CertType) -> Self {
        let (key_usage, extended_key_usage) = match cert_type {
            CertType::RootCA | CertType::IntermediateCA => (
                vec![
                    KeyUsage::DigitalSignature,
                    KeyUsage::KeyCertSign,
                    KeyUsage::CrlSign,
                ],
                vec![],
            ),
            CertType::Server => (
                vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
                vec![ExtendedKeyUsage::ServerAuth],
            ),
            CertType::Client => (
                vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
                vec![ExtendedKeyUsage::ClientAuth],
            ),
            CertType::Both => (
                vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
                vec![
                    ExtendedKeyUsage::ServerAuth,
                    ExtendedKeyUsage::ClientAuth,
                ],
            ),
        };

        Self {
            subject: DistinguishedName::new(cn),
            san: SubjectAltName::new(),
            cert_type,
            validity_days: 365,
            key_usage,
            extended_key_usage,
            crl_distribution_points: Vec::new(),
            ocsp_servers: Vec::new(),
        }
    }

    pub fn with_subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = subject;
        self
    }

    pub fn with_san(mut self, san: SubjectAltName) -> Self {
        self.san = san;
        self
    }

    pub fn with_validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    pub fn with_crl_dp(mut self, url: impl Into<String>) -> Self {
        self.crl_distribution_points.push(url.into());
        self
    }

    pub fn with_ocsp(mut self, url: impl Into<String>) -> Self {
        self.ocsp_servers.push(url.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    DigitalSignature,
    KeyEncipherment,
    KeyAgreement,
    KeyCertSign,
    CrlSign,
    DataEncipherment,
    NonRepudiation,
}

impl KeyUsage {
    pub fn to_rcgen(&self) -> rcgen::KeyUsagePurpose {
        match self {
            KeyUsage::DigitalSignature => rcgen::KeyUsagePurpose::DigitalSignature,
            KeyUsage::KeyEncipherment => rcgen::KeyUsagePurpose::KeyEncipherment,
            KeyUsage::KeyAgreement => rcgen::KeyUsagePurpose::KeyAgreement,
            KeyUsage::KeyCertSign => rcgen::KeyUsagePurpose::KeyCertSign,
            KeyUsage::CrlSign => rcgen::KeyUsagePurpose::CrlSign,
            KeyUsage::DataEncipherment => rcgen::KeyUsagePurpose::DataEncipherment,
            KeyUsage::NonRepudiation => rcgen::KeyUsagePurpose::ContentCommitment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
}

impl ExtendedKeyUsage {
    pub fn to_rcgen(&self) -> rcgen::ExtendedKeyUsagePurpose {
        match self {
            ExtendedKeyUsage::ServerAuth => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsage::ClientAuth => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsage::CodeSigning => rcgen::ExtendedKeyUsagePurpose::CodeSigning,
            ExtendedKeyUsage::EmailProtection => rcgen::ExtendedKeyUsagePurpose::EmailProtection,
            ExtendedKeyUsage::TimeStamping => rcgen::ExtendedKeyUsagePurpose::TimeStamping,
            ExtendedKeyUsage::OcspSigning => rcgen::ExtendedKeyUsagePurpose::OcspSigning,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    pub serial_number: Vec<u8>,
    pub revocation_time: DateTime<Utc>,
    pub reason: RevocationReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCRL,
    PrivilegeWithdrawn,
    AACompromise,
}

impl RevocationReason {
    pub fn to_code(&self) -> i32 {
        match self {
            RevocationReason::Unspecified => 0,
            RevocationReason::KeyCompromise => 1,
            RevocationReason::CACompromise => 2,
            RevocationReason::AffiliationChanged => 3,
            RevocationReason::Superseded => 4,
            RevocationReason::CessationOfOperation => 5,
            RevocationReason::CertificateHold => 6,
            RevocationReason::RemoveFromCRL => 8,
            RevocationReason::PrivilegeWithdrawn => 9,
            RevocationReason::AACompromise => 10,
        }
    }
}

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "json")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub subject_alt_names: Vec<String>,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
}
