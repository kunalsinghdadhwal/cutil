use crate::error::{Error, Result};
use crate::types::{
    CertSigAlgo, CertType, CertificateRequest, DistinguishedName, RevocationReason,
    RevokedCertificate, SubjectAltName,
};
use chrono::{DateTime, Duration, Utc};
use rcgen::{Certificate, CertificateParams, KeyPair};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct CertificateAuthority {
    certificate: Certificate,
    cert_pem: String,
    key_pem: String,
    next_serial: u64,
    revoked_certs: Vec<RevokedCertificate>,
    algorithm: CertSigAlgo,
    chain: Vec<String>,
}

impl CertificateAuthority {
    pub fn new_root(
        subject: DistinguishedName,
        algorithm: CertSigAlgo,
        validity_days: u32,
    ) -> Result<Self> {
        let key_pair = algorithm.key_pair()?;

        let mut params = CertificateParams::new(vec![]);
        params.distinguished_name = subject.to_rcgen();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let not_before = chrono::Utc::now();
        let not_after = not_before + Duration::days(validity_days as i64);
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
            .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
            .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;

        params.alg = algorithm.to_rcgen();
        params.key_pair = Some(key_pair);

        let serial: u64 = 1;
        params.serial_number = Some(rcgen::SerialNumber::from(serial));

        let certificate = Certificate::from_params(params)?;
        let cert_pem = certificate.serialize_pem()?;
        let key_pem = certificate.serialize_private_key_pem();

        Ok(Self {
            certificate,
            cert_pem,
            key_pem,
            next_serial: 2,
            revoked_certs: Vec::new(),
            algorithm,
            chain: Vec::new(),
        })
    }

    pub fn new_intermediate(
        subject: DistinguishedName,
        algorithm: CertSigAlgo,
        validity_days: u32,
        parent_ca: &CertificateAuthority,
    ) -> Result<Self> {
        let key_pair = algorithm.key_pair()?;

        let mut params = CertificateParams::new(vec![]);
        params.distinguished_name = subject.to_rcgen();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let not_before = chrono::Utc::now();
        let not_after = not_before + Duration::days(validity_days as i64);
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
            .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
            .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;

        params.alg = algorithm.to_rcgen();
        params.key_pair = Some(key_pair);

        let certificate = Certificate::from_params(params)?;
        let cert_pem = certificate.serialize_pem_with_signer(&parent_ca.certificate)?;
        let key_pem = certificate.serialize_private_key_pem();

        let mut chain = parent_ca.chain.clone();
        chain.insert(0, parent_ca.cert_pem.clone());

        Ok(Self {
            certificate,
            cert_pem,
            key_pem,
            next_serial: 1,
            revoked_certs: Vec::new(),
            algorithm,
            chain,
        })
    }

    pub fn issue_certificate(
        &mut self,
        request: &CertificateRequest,
        algorithm: CertSigAlgo,
    ) -> Result<IssuedCertificate> {
        let key_pair = algorithm.key_pair()?;

        let mut params = CertificateParams::new(vec![]);
        params.distinguished_name = request.subject.to_rcgen();

        let mut san_vec = Vec::new();
        for dns in &request.san.dns_names {
            san_vec.push(rcgen::SanType::DnsName(dns.clone()));
        }
        for ip in &request.san.ip_addresses {
            san_vec.push(rcgen::SanType::IpAddress(*ip));
        }
        for email in &request.san.email_addresses {
            san_vec.push(rcgen::SanType::Rfc822Name(email.clone()));
        }
        params.subject_alt_names = san_vec;

        params.is_ca = match request.cert_type {
            CertType::RootCA | CertType::IntermediateCA => {
                rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0))
            }
            _ => rcgen::IsCa::NoCa,
        };

        params.key_usages = request.key_usage.iter().map(|ku| ku.to_rcgen()).collect();

        params.extended_key_usages = request
            .extended_key_usage
            .iter()
            .map(|eku| eku.to_rcgen())
            .collect();

        if !request.crl_distribution_points.is_empty() {
            params.crl_distribution_points = request.crl_distribution_points.clone();
        }

        let not_before = chrono::Utc::now();
        let not_after = not_before + Duration::days(request.validity_days as i64);
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before.timestamp())
            .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after.timestamp())
            .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;

        params.alg = algorithm.to_rcgen();
        params.key_pair = Some(key_pair);

        let serial = self.next_serial;
        self.next_serial += 1;
        params.serial_number = Some(rcgen::SerialNumber::from(serial));

        let certificate = Certificate::from_params(params)?;
        let cert_pem = certificate.serialize_pem_with_signer(&self.certificate)?;
        let key_pem = certificate.serialize_private_key_pem();

        let mut chain = vec![self.cert_pem.clone()];
        chain.extend(self.chain.iter().cloned());

        Ok(IssuedCertificate {
            cert_pem,
            key_pem,
            chain,
            serial_number: serial.to_be_bytes().to_vec(),
        })
    }

    pub fn revoke_certificate(
        &mut self,
        serial_number: Vec<u8>,
        reason: RevocationReason,
    ) -> Result<()> {
        if self
            .revoked_certs
            .iter()
            .any(|r| r.serial_number == serial_number)
        {
            return Err(Error::AlreadyRevoked(hex::encode(&serial_number)));
        }

        self.revoked_certs.push(RevokedCertificate {
            serial_number,
            revocation_time: Utc::now(),
            reason,
        });

        Ok(())
    }

    pub fn generate_crl(&self) -> Result<String> {
        let mut params = rcgen::CrlParams::default();

        params.this_update = time::OffsetDateTime::now_utc();
        params.next_update = time::OffsetDateTime::now_utc() + time::Duration::days(7);

        for revoked in &self.revoked_certs {
            let serial = rcgen::SerialNumber::from_slice(&revoked.serial_number);
            let revocation_time =
                time::OffsetDateTime::from_unix_timestamp(revoked.revocation_time.timestamp())
                    .map_err(|e| Error::CertGen(format!("Invalid timestamp: {}", e)))?;

            params.revoked_certs.push(rcgen::RevokedCertParams {
                serial_number: serial,
                revocation_time,
                reason_code: Some(rcgen::RevocationReason::from_u8(
                    revoked.reason.to_code() as u8
                )),
                invalidity_date: None,
            });
        }

        let crl = params.serialize_der_with_signer(&self.certificate)?;
        Ok(format!(
            "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
            base64_encode(&crl)
        ))
    }

    pub fn save_pem(&self, cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<()> {
        fs::write(cert_path, &self.cert_pem)?;
        fs::write(key_path, &self.key_pem)?;
        Ok(())
    }

    pub fn load_pem(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        algorithm: CertSigAlgo,
    ) -> Result<Self> {
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;

        let key_pair = KeyPair::from_pem(&key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
        let mut params_with_key = params;
        params_with_key.key_pair = Some(key_pair);

        let certificate = Certificate::from_params(params_with_key)?;

        Ok(Self {
            certificate,
            cert_pem,
            key_pem,
            next_serial: 1000,
            revoked_certs: Vec::new(),
            algorithm,
            chain: Vec::new(),
        })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    pub fn chain(&self) -> &[String] {
        &self.chain
    }

    pub fn revoked_certificates(&self) -> &[RevokedCertificate] {
        &self.revoked_certs
    }
}

#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub chain: Vec<String>,
    pub serial_number: Vec<u8>,
}

impl IssuedCertificate {
    pub fn save_pem(&self, cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<()> {
        fs::write(cert_path, &self.cert_pem)?;
        fs::write(key_path, &self.key_pem)?;
        Ok(())
    }

    pub fn save_chain(&self, chain_path: impl AsRef<Path>) -> Result<()> {
        let mut full_chain = self.cert_pem.clone();
        for cert in &self.chain {
            full_chain.push_str(cert);
        }
        fs::write(chain_path, full_chain)?;
        Ok(())
    }

    pub fn export_pkcs12(&self, password: &str, friendly_name: &str) -> Result<Vec<u8>> {
        let cert_der = pem_to_der(&self.cert_pem)?;
        let key_der = pem_to_der(&self.key_pem)?;

        let mut chain_der = Vec::new();
        for cert_pem in &self.chain {
            chain_der.push(pem_to_der(cert_pem)?);
        }

        let pfx = p12::PFX::new(
            &cert_der,
            &key_der,
            Some(&chain_der),
            password,
            Some(friendly_name),
        )
        .map_err(|e| Error::Pkcs12(e.to_string()))?;

        pfx.to_der().map_err(|e| Error::Pkcs12(e.to_string()))
    }
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let pem_trimmed = pem.trim();
    let lines: Vec<&str> = pem_trimmed.lines().collect();

    let start_idx = lines
        .iter()
        .position(|line| line.starts_with("-----BEGIN"))
        .ok_or_else(|| Error::Pem("Invalid PEM format: no BEGIN marker".to_string()))?;

    let end_idx = lines
        .iter()
        .position(|line| line.starts_with("-----END"))
        .ok_or_else(|| Error::Pem("Invalid PEM format: no END marker".to_string()))?;

    let base64_data = lines[start_idx + 1..end_idx].join("");

    base64_decode(&base64_data).map_err(|e| Error::Pem(format!("Base64 decode error: {}", e)))
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut output = String::new();
    let encoded = base64_simd::STANDARD.encode_to_string(data);

    for (i, chunk) in encoded.as_bytes().chunks(64).enumerate() {
        if i > 0 {
            output.push('\n');
        }
        output.push_str(std::str::from_utf8(chunk).unwrap());
    }
    output
}

fn base64_decode(data: &str) -> std::result::Result<Vec<u8>, String> {
    base64_simd::STANDARD
        .decode_to_vec(data)
        .map_err(|e| e.to_string())
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

mod base64_simd {
    pub struct Encoding;

    pub const STANDARD: Encoding = Encoding;

    impl Encoding {
        pub fn encode_to_string(&self, data: &[u8]) -> String {
            base64_encode_simple(data)
        }

        pub fn decode_to_vec(&self, data: &str) -> std::result::Result<Vec<u8>, String> {
            base64_decode_simple(data)
        }
    }

    fn base64_encode_simple(data: &[u8]) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = Vec::new();

        for chunk in data.chunks(3) {
            let mut buf = [0u8; 3];
            for (i, &byte) in chunk.iter().enumerate() {
                buf[i] = byte;
            }

            let b1 = (buf[0] >> 2) & 0x3F;
            let b2 = ((buf[0] & 0x03) << 4) | ((buf[1] >> 4) & 0x0F);
            let b3 = ((buf[1] & 0x0F) << 2) | ((buf[2] >> 6) & 0x03);
            let b4 = buf[2] & 0x3F;

            result.push(CHARSET[b1 as usize]);
            result.push(CHARSET[b2 as usize]);
            result.push(if chunk.len() > 1 {
                CHARSET[b3 as usize]
            } else {
                b'='
            });
            result.push(if chunk.len() > 2 {
                CHARSET[b4 as usize]
            } else {
                b'='
            });
        }

        String::from_utf8(result).unwrap()
    }

    fn base64_decode_simple(data: &str) -> std::result::Result<Vec<u8>, String> {
        let data = data.replace(['\n', '\r', ' '], "");
        let data = data.as_bytes();

        if data.len() % 4 != 0 {
            return Err("Invalid base64 length".to_string());
        }

        let mut result = Vec::new();

        for chunk in data.chunks(4) {
            let mut buf = [0u8; 4];
            for (i, &byte) in chunk.iter().enumerate() {
                buf[i] = match byte {
                    b'A'..=b'Z' => byte - b'A',
                    b'a'..=b'z' => byte - b'a' + 26,
                    b'0'..=b'9' => byte - b'0' + 52,
                    b'+' => 62,
                    b'/' => 63,
                    b'=' => 0,
                    _ => return Err(format!("Invalid base64 character: {}", byte as char)),
                };
            }

            result.push((buf[0] << 2) | (buf[1] >> 4));
            if chunk[2] != b'=' {
                result.push((buf[1] << 4) | (buf[2] >> 2));
            }
            if chunk[3] != b'=' {
                result.push((buf[2] << 6) | buf[3]);
            }
        }

        Ok(result)
    }
}
