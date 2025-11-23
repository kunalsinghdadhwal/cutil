use crate::error::{Error, Result};
use colored::Colorize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct CertificateChainInfo {
    pub certificates: Vec<ParsedCertificate>,
}

#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_size: Option<usize>,
    pub subject_alt_names: Vec<String>,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub is_valid: bool,
    pub validity_status: String,
}

#[derive(Debug)]
struct CertificateCapture {
    certificates: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CertificateCapture {
    fn new() -> Self {
        Self {
            certificates: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_certificates(&self) -> Vec<Vec<u8>> {
        self.certificates.lock().unwrap().clone()
    }

    fn add_certificate(&self, cert: Vec<u8>) {
        self.certificates.lock().unwrap().push(cert);
    }
}

pub fn fetch_certificate_chain(host: &str, port: u16) -> Result<CertificateChainInfo> {
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls::pki_types::UnixTime;

    struct SimpleVerifier {
        certs: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ServerCertVerifier for SimpleVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            let mut certs = self.certs.lock().unwrap();
            certs.clear();
            certs.push(end_entity.to_vec());
            for cert in intermediates {
                certs.push(cert.to_vec());
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| Error::DnsName(format!("Invalid DNS name '{}': {}", host, e)))?;

    let cert_storage = Arc::new(Mutex::new(Vec::new()));
    let verifier = Arc::new(SimpleVerifier { certs: cert_storage.clone() });

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| Error::Tls(format!("Failed to create TLS connection: {}", e)))?;

    let addr = format!("{}:{}", host, port);
    let mut sock = TcpStream::connect(&addr)
        .map_err(|e| Error::Connection(format!("Failed to connect to {}: {}", addr, e)))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    tls.write_all(request.as_bytes())
        .map_err(|e| Error::Connection(format!("Failed to send request: {}", e)))?;

    let mut response = vec![0u8; 1024];
    let _ = tls.read(&mut response);

    let raw_certs = cert_storage.lock().unwrap().clone();
    if raw_certs.is_empty() {
        return Err(Error::NotFound("No certificates received".to_string()));
    }

    let mut certificates = Vec::new();
    for cert_der in raw_certs {
        let parsed = parse_certificate(&cert_der)?;
        certificates.push(parsed);
    }

    Ok(CertificateChainInfo { certificates })
}

fn parse_certificate(cert_der: &[u8]) -> Result<ParsedCertificate> {
    let (_, x509) = X509Certificate::from_der(cert_der)
        .map_err(|e| Error::CertParse(format!("Failed to parse certificate: {}", e)))?;

    let subject = format_dn(&x509.subject);
    let issuer = format_dn(&x509.issuer);
    let serial_number = format_serial(x509.serial.to_bytes_be().as_slice());

    let not_before = x509.validity.not_before.to_string();
    let not_after = x509.validity.not_after.to_string();

    let now = chrono::Utc::now().timestamp();
    let not_before_ts = x509.validity.not_before.timestamp();
    let not_after_ts = x509.validity.not_after.timestamp();

    let is_valid = now >= not_before_ts && now <= not_after_ts;
    let validity_status = if now < not_before_ts {
        "Not yet valid".to_string()
    } else if now > not_after_ts {
        "Expired".to_string()
    } else {
        "Valid".to_string()
    };

    let signature_algorithm = x509.signature_algorithm.algorithm.to_string();

    let (public_key_algorithm, public_key_size) = match x509.public_key().parsed() {
        Ok(x509_parser::public_key::PublicKey::RSA(rsa)) => {
            let size = rsa.key_size();
            ("RSA".to_string(), Some(size * 8))
        }
        Ok(x509_parser::public_key::PublicKey::EC(_)) => ("ECDSA".to_string(), None),
        Ok(x509_parser::public_key::PublicKey::DSA(_)) => ("DSA".to_string(), None),
        Ok(x509_parser::public_key::PublicKey::Unknown(_)) => ("Unknown".to_string(), None),
        _ => ("Unknown".to_string(), None),
    };

    let mut subject_alt_names = Vec::new();
    if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
        for san in &san_ext.value.general_names {
            match san {
                GeneralName::DNSName(name) => {
                    subject_alt_names.push(format!("DNS:{}", name));
                }
                GeneralName::IPAddress(ip) => {
                    subject_alt_names.push(format!("IP:{}", format_ip(ip)));
                }
                GeneralName::RFC822Name(email) => {
                    subject_alt_names.push(format!("Email:{}", email));
                }
                GeneralName::URI(uri) => {
                    subject_alt_names.push(format!("URI:{}", uri));
                }
                _ => {}
            }
        }
    }

    let is_ca = x509
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    let mut key_usage = Vec::new();
    if let Ok(Some(ku_ext)) = x509.key_usage() {
        let ku = &ku_ext.value;
        if ku.digital_signature() {
            key_usage.push("Digital Signature".to_string());
        }
        if ku.non_repudiation() {
            key_usage.push("Non Repudiation".to_string());
        }
        if ku.key_encipherment() {
            key_usage.push("Key Encipherment".to_string());
        }
        if ku.data_encipherment() {
            key_usage.push("Data Encipherment".to_string());
        }
        if ku.key_agreement() {
            key_usage.push("Key Agreement".to_string());
        }
        if ku.key_cert_sign() {
            key_usage.push("Certificate Sign".to_string());
        }
        if ku.crl_sign() {
            key_usage.push("CRL Sign".to_string());
        }
    }

    let mut extended_key_usage = Vec::new();
    if let Ok(Some(eku_ext)) = x509.extended_key_usage() {
        for oid in &eku_ext.value.other {
            let eku_name = match oid.to_string().as_str() {
                "1.3.6.1.5.5.7.3.1" => "TLS Web Server Authentication",
                "1.3.6.1.5.5.7.3.2" => "TLS Web Client Authentication",
                "1.3.6.1.5.5.7.3.3" => "Code Signing",
                "1.3.6.1.5.5.7.3.4" => "Email Protection",
                "1.3.6.1.5.5.7.3.8" => "Time Stamping",
                "1.3.6.1.5.5.7.3.9" => "OCSP Signing",
                _ => "Unknown",
            };
            extended_key_usage.push(eku_name.to_string());
        }
    }

    Ok(ParsedCertificate {
        subject,
        issuer,
        serial_number,
        not_before,
        not_after,
        signature_algorithm,
        public_key_algorithm,
        public_key_size,
        subject_alt_names,
        is_ca,
        key_usage,
        extended_key_usage,
        is_valid,
        validity_status,
    })
}

fn format_dn(dn: &X509Name) -> String {
    let mut parts = Vec::new();

    for rdn in dn.iter() {
        for attr in rdn.iter() {
            let attr_type = attr.attr_type();
            let attr_value = attr.attr_value().as_str().unwrap_or("?");

            let name = match attr_type.to_string().as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                _ => continue,
            };

            parts.push(format!("{}={}", name, attr_value));
        }
    }

    parts.join(", ")
}

fn format_serial(serial: &[u8]) -> String {
    serial
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_ip(ip_bytes: &[u8]) -> String {
    if ip_bytes.len() == 4 {
        format!(
            "{}.{}.{}.{}",
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
        )
    } else if ip_bytes.len() == 16 {
        let mut parts = Vec::new();
        for i in (0..16).step_by(2) {
            parts.push(format!("{:02x}{:02x}", ip_bytes[i], ip_bytes[i + 1]));
        }
        parts.join(":")
    } else {
        format!("{:?}", ip_bytes)
    }
}

pub fn display_certificate_chain(
    chain: &CertificateChainInfo,
    format: OutputFormat,
) -> Result<String> {
    match format {
        OutputFormat::Pretty => display_pretty(chain),
        #[cfg(feature = "json")]
        OutputFormat::Json => display_json(chain),
    }
}

pub enum OutputFormat {
    Pretty,
    #[cfg(feature = "json")]
    Json,
}

fn display_pretty(chain: &CertificateChainInfo) -> Result<String> {
    let mut output = String::new();

    output.push_str(&format!("\n{}\n", "Certificate Chain".bold().cyan()));
    output.push_str(&format!("{}\n\n", "=".repeat(80)));

    for (idx, cert) in chain.certificates.iter().enumerate() {
        let cert_label = if idx == 0 {
            "End-Entity Certificate"
        } else if idx == chain.certificates.len() - 1 {
            "Root CA Certificate"
        } else {
            "Intermediate CA Certificate"
        };

        output.push_str(&format!(
            "{} {}\n",
            "Certificate".bold(),
            format!("[{}]", idx).dimmed()
        ));
        output.push_str(&format!("{}: {}\n", "Type".bold(), cert_label));
        output.push_str(&format!("{}\n", "-".repeat(80)));

        output.push_str(&format!(
            "  {}: {}\n",
            "Subject".bold().yellow(),
            cert.subject
        ));
        output.push_str(&format!(
            "  {}: {}\n",
            "Issuer".bold().yellow(),
            cert.issuer
        ));
        output.push_str(&format!(
            "  {}: {}\n",
            "Serial Number".bold().yellow(),
            cert.serial_number
        ));

        let validity_color = if cert.is_valid {
            cert.validity_status.green()
        } else {
            cert.validity_status.red()
        };
        output.push_str(&format!(
            "  {}: {}\n",
            "Validity Status".bold().yellow(),
            validity_color
        ));
        output.push_str(&format!(
            "  {}: {}\n",
            "Not Before".bold().yellow(),
            cert.not_before.dimmed()
        ));
        output.push_str(&format!(
            "  {}: {}\n",
            "Not After".bold().yellow(),
            cert.not_after.dimmed()
        ));

        output.push_str(&format!(
            "  {}: {}\n",
            "Signature Algorithm".bold().yellow(),
            cert.signature_algorithm.dimmed()
        ));

        let pk_info = if let Some(size) = cert.public_key_size {
            format!("{} ({} bits)", cert.public_key_algorithm, size)
        } else {
            cert.public_key_algorithm.clone()
        };
        output.push_str(&format!(
            "  {}: {}\n",
            "Public Key".bold().yellow(),
            pk_info.dimmed()
        ));

        if cert.is_ca {
            output.push_str(&format!(
                "  {}: {}\n",
                "CA Certificate".bold().yellow(),
                "Yes".green()
            ));
        }

        if !cert.subject_alt_names.is_empty() {
            output.push_str(&format!(
                "  {}:\n",
                "Subject Alternative Names".bold().yellow()
            ));
            for san in &cert.subject_alt_names {
                output.push_str(&format!("    - {}\n", san.cyan()));
            }
        }

        if !cert.key_usage.is_empty() {
            output.push_str(&format!(
                "  {}: {}\n",
                "Key Usage".bold().yellow(),
                cert.key_usage.join(", ").dimmed()
            ));
        }

        if !cert.extended_key_usage.is_empty() {
            output.push_str(&format!(
                "  {}: {}\n",
                "Extended Key Usage".bold().yellow(),
                cert.extended_key_usage.join(", ").dimmed()
            ));
        }

        output.push_str("\n");
    }

    output.push_str(&format!("{}\n", "=".repeat(80)));
    output.push_str(&format!(
        "{}: {}\n",
        "Total Certificates".bold().cyan(),
        chain.certificates.len()
    ));

    Ok(output)
}

#[cfg(feature = "json")]
fn display_json(chain: &CertificateChainInfo) -> Result<String> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct JsonCertificate {
        subject: String,
        issuer: String,
        serial_number: String,
        not_before: String,
        not_after: String,
        signature_algorithm: String,
        public_key_algorithm: String,
        public_key_size: Option<usize>,
        subject_alt_names: Vec<String>,
        is_ca: bool,
        key_usage: Vec<String>,
        extended_key_usage: Vec<String>,
        is_valid: bool,
        validity_status: String,
    }

    #[derive(Serialize)]
    struct JsonChain {
        total_certificates: usize,
        certificates: Vec<JsonCertificate>,
    }

    let json_certs: Vec<JsonCertificate> = chain
        .certificates
        .iter()
        .map(|cert| JsonCertificate {
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            serial_number: cert.serial_number.clone(),
            not_before: cert.not_before.clone(),
            not_after: cert.not_after.clone(),
            signature_algorithm: cert.signature_algorithm.clone(),
            public_key_algorithm: cert.public_key_algorithm.clone(),
            public_key_size: cert.public_key_size,
            subject_alt_names: cert.subject_alt_names.clone(),
            is_ca: cert.is_ca,
            key_usage: cert.key_usage.clone(),
            extended_key_usage: cert.extended_key_usage.clone(),
            is_valid: cert.is_valid,
            validity_status: cert.validity_status.clone(),
        })
        .collect();

    let json_chain = JsonChain {
        total_certificates: chain.certificates.len(),
        certificates: json_certs,
    };

    serde_json::to_string_pretty(&json_chain).map_err(|e| Error::Serialization(e.to_string()))
}

pub fn save_chain_to_file(chain: &CertificateChainInfo, path: &str) -> Result<()> {
    let mut output = String::new();

    for (idx, _) in chain.certificates.iter().enumerate() {
        output.push_str(&format!("Certificate {}\n", idx));
        output.push_str("(PEM encoding not available from fetched certificates)\n\n");
    }

    std::fs::write(path, output).map_err(|e| Error::Io(e))?;

    Ok(())
}
