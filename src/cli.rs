#[cfg(feature = "cli")]
use crate::ca::CertificateAuthority;
#[cfg(feature = "cli")]
use crate::cert::CertificateBuilder;
#[cfg(feature = "cli")]
use crate::error::Result;
#[cfg(feature = "cli")]
use crate::fetch::{display_certificate_chain, fetch_certificate_chain, OutputFormat};
#[cfg(feature = "cli")]
use crate::types::{CertSigAlgo, CertType, DistinguishedName, RevocationReason};
#[cfg(feature = "cli")]
use clap::{Parser, Subcommand};
#[cfg(feature = "cli")]
use colored::Colorize;
#[cfg(feature = "cli")]
use std::path::PathBuf;

#[cfg(feature = "cli")]
#[derive(Parser)]
#[command(name = "certutil")]
#[command(version, about = "A complete internal PKI toolkit", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[cfg(feature = "cli")]
#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Initialize a new Certificate Authority")]
    Init {
        #[arg(short, long, help = "Common name for the CA")]
        cn: String,

        #[arg(short, long, help = "Organization name")]
        org: Option<String>,

        #[arg(short = 'u', long, help = "Organizational unit")]
        ou: Option<String>,

        #[arg(short = 'C', long, help = "Country code (2 letters)")]
        country: Option<String>,

        #[arg(short = 'S', long, help = "State or province")]
        state: Option<String>,

        #[arg(short = 'L', long, help = "Locality or city")]
        locality: Option<String>,

        #[arg(
            short,
            long,
            default_value = "ecdsa-p256",
            help = "Signature algorithm"
        )]
        algorithm: String,

        #[arg(short, long, default_value = "3650", help = "Validity in days")]
        validity: u32,

        #[arg(long, default_value = "ca.pem", help = "CA certificate output path")]
        cert_out: PathBuf,

        #[arg(
            long,
            default_value = "ca-key.pem",
            help = "CA private key output path"
        )]
        key_out: PathBuf,

        #[arg(
            long,
            help = "Create intermediate CA (requires parent CA cert and key)"
        )]
        intermediate: bool,

        #[arg(long, help = "Parent CA certificate (for intermediate CA)")]
        parent_cert: Option<PathBuf>,

        #[arg(long, help = "Parent CA key (for intermediate CA)")]
        parent_key: Option<PathBuf>,
    },

    #[command(about = "Issue a new certificate")]
    Cert {
        #[arg(short, long, help = "Common name for the certificate")]
        cn: String,

        #[arg(
            short,
            long,
            default_value = "server",
            help = "Certificate type: server, client, both"
        )]
        cert_type: String,

        #[arg(
            short,
            long,
            help = "DNS Subject Alternative Names",
            value_delimiter = ','
        )]
        dns: Vec<String>,

        #[arg(
            short,
            long,
            help = "IP Subject Alternative Names",
            value_delimiter = ','
        )]
        ip: Vec<String>,

        #[arg(short, long, help = "Email Subject Alternative Name")]
        email: Option<String>,

        #[arg(short, long, help = "Organization name")]
        org: Option<String>,

        #[arg(short = 'u', long, help = "Organizational unit")]
        ou: Option<String>,

        #[arg(
            short,
            long,
            default_value = "ecdsa-p256",
            help = "Signature algorithm"
        )]
        algorithm: String,

        #[arg(short, long, default_value = "365", help = "Validity in days")]
        validity: u32,

        #[arg(long, default_value = "ca.pem", help = "CA certificate path")]
        ca_cert: PathBuf,

        #[arg(long, default_value = "ca-key.pem", help = "CA key path")]
        ca_key: PathBuf,

        #[arg(long, default_value = "cert.pem", help = "Certificate output path")]
        cert_out: PathBuf,

        #[arg(long, default_value = "cert-key.pem", help = "Private key output path")]
        key_out: PathBuf,

        #[arg(long, help = "Output full chain file")]
        chain_out: Option<PathBuf>,

        #[arg(long, help = "Export as PKCS#12 (.p12/.pfx)")]
        p12_out: Option<PathBuf>,

        #[arg(long, help = "PKCS#12 password")]
        p12_password: Option<String>,

        #[arg(long, help = "CRL distribution point URL")]
        crl_url: Option<String>,

        #[arg(long, help = "OCSP server URL")]
        ocsp_url: Option<String>,
    },

    #[command(about = "Fetch and inspect remote certificate chain")]
    Fetch {
        #[arg(help = "Target host:port (e.g., example.com:443)")]
        target: String,

        #[arg(
            short,
            long,
            default_value = "pretty",
            help = "Output format: pretty or json"
        )]
        format: String,

        #[arg(short, long, help = "Save chain info to file")]
        output: Option<PathBuf>,
    },

    #[command(about = "Revoke a certificate")]
    Revoke {
        #[arg(short, long, help = "Serial number (hex format)")]
        serial: String,

        #[arg(short, long, default_value = "unspecified", help = "Revocation reason")]
        reason: String,

        #[arg(long, default_value = "ca.pem", help = "CA certificate path")]
        ca_cert: PathBuf,

        #[arg(long, default_value = "ca-key.pem", help = "CA key path")]
        ca_key: PathBuf,
    },

    #[command(about = "Generate Certificate Revocation List")]
    Crl {
        #[arg(long, default_value = "ca.pem", help = "CA certificate path")]
        ca_cert: PathBuf,

        #[arg(long, default_value = "ca-key.pem", help = "CA key path")]
        ca_key: PathBuf,

        #[arg(short, long, default_value = "crl.pem", help = "CRL output path")]
        output: PathBuf,
    },

    #[command(about = "Display full certificate chain")]
    Chain {
        #[arg(help = "Certificate file path")]
        cert_path: PathBuf,
    },
}

#[cfg(feature = "cli")]
pub fn run_cli() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            cn,
            org,
            ou,
            country,
            state,
            locality,
            algorithm,
            validity,
            cert_out,
            key_out,
            intermediate,
            parent_cert,
            parent_key,
        } => {
            let algo = algorithm.parse::<CertSigAlgo>()?;
            let mut subject = DistinguishedName::new(cn);

            if let Some(o) = org {
                subject = subject.with_organization(o);
            }
            if let Some(u) = ou {
                subject = subject.with_organizational_unit(u);
            }
            if let Some(c) = country {
                subject = subject.with_country(c);
            }
            if let Some(s) = state {
                subject = subject.with_state(s);
            }
            if let Some(l) = locality {
                subject = subject.with_locality(l);
            }

            if intermediate {
                let parent_cert_path = parent_cert.ok_or_else(|| {
                    crate::error::Error::InvalidInput(
                        "Parent CA certificate required for intermediate CA".to_string(),
                    )
                })?;
                let parent_key_path = parent_key.ok_or_else(|| {
                    crate::error::Error::InvalidInput(
                        "Parent CA key required for intermediate CA".to_string(),
                    )
                })?;

                let parent_ca =
                    CertificateAuthority::load_pem(parent_cert_path, parent_key_path, algo)?;

                let ca =
                    CertificateAuthority::new_intermediate(subject, algo, validity, &parent_ca)?;
                ca.save_pem(&cert_out, &key_out)?;

                println!("{}", "Intermediate CA created successfully!".green().bold());
            } else {
                let ca = CertificateAuthority::new_root(subject, algo, validity)?;
                ca.save_pem(&cert_out, &key_out)?;

                println!("{}", "Root CA created successfully!".green().bold());
            }

            println!("  {}: {}", "Certificate".cyan(), cert_out.display());
            println!("  {}: {}", "Private Key".cyan(), key_out.display());
            println!("  {}: {}", "Algorithm".cyan(), algo.name());
            println!("  {}: {} days", "Validity".cyan(), validity);
        }

        Commands::Cert {
            cn,
            cert_type,
            dns,
            ip,
            email,
            org,
            ou,
            algorithm,
            validity,
            ca_cert,
            ca_key,
            cert_out,
            key_out,
            chain_out,
            p12_out,
            p12_password,
            crl_url,
            ocsp_url,
        } => {
            let algo = algorithm.parse::<CertSigAlgo>()?;
            let mut ca = CertificateAuthority::load_pem(ca_cert, ca_key, algo)?;

            let c_type = match cert_type.to_lowercase().as_str() {
                "server" => CertType::Server,
                "client" => CertType::Client,
                "both" => CertType::Both,
                _ => {
                    return Err(crate::error::Error::InvalidInput(format!(
                        "Invalid cert type: {}",
                        cert_type
                    )))
                }
            };

            let mut builder = CertificateBuilder::new(cn, c_type)
                .with_algorithm(algo)
                .with_validity_days(validity);

            let mut subject = DistinguishedName::new(builder.build().0.subject.common_name.clone());
            if let Some(o) = org {
                subject = subject.with_organization(o);
            }
            if let Some(u) = ou {
                subject = subject.with_organizational_unit(u);
            }
            builder = builder.with_subject(subject);

            for d in dns {
                builder = builder.with_dns_san(d);
            }

            for ip_str in ip {
                if let Ok(ip_addr) = ip_str.parse() {
                    builder = builder.with_ip_san(ip_addr);
                }
            }

            if let Some(e) = email {
                builder = builder.with_email_san(e);
            }

            if let Some(crl) = crl_url {
                builder = builder.with_crl_distribution_point(crl);
            }

            if let Some(ocsp) = ocsp_url {
                builder = builder.with_ocsp_server(ocsp);
            }

            let issued = builder.issue(&mut ca)?;
            issued.save_pem(&cert_out, &key_out)?;

            println!("{}", "Certificate issued successfully!".green().bold());
            println!("  {}: {}", "Certificate".cyan(), cert_out.display());
            println!("  {}: {}", "Private Key".cyan(), key_out.display());

            if let Some(chain_path) = chain_out {
                issued.save_chain(&chain_path)?;
                println!("  {}: {}", "Full Chain".cyan(), chain_path.display());
            }

            if let Some(p12_path) = p12_out {
                let password = p12_password.unwrap_or_else(|| "changeit".to_string());
                let p12_data = issued.export_pkcs12(&password, "certificate")?;
                std::fs::write(&p12_path, p12_data)?;
                println!("  {}: {}", "PKCS#12".cyan(), p12_path.display());
            }
        }

        Commands::Fetch {
            target,
            format,
            output,
        } => {
            let parts: Vec<&str> = target.split(':').collect();
            if parts.len() != 2 {
                return Err(crate::error::Error::InvalidInput(
                    "Target must be in format host:port".to_string(),
                ));
            }

            let host = parts[0];
            let port: u16 = parts[1].parse().map_err(|_| {
                crate::error::Error::InvalidInput("Invalid port number".to_string())
            })?;

            println!(
                "{}",
                format!("Fetching certificate chain from {}...", target).cyan()
            );

            let chain = fetch_certificate_chain(host, port)?;

            let output_format = match format.to_lowercase().as_str() {
                "pretty" => OutputFormat::Pretty,
                #[cfg(feature = "json")]
                "json" => OutputFormat::Json,
                _ => {
                    return Err(crate::error::Error::InvalidInput(format!(
                        "Invalid format: {}",
                        format
                    )))
                }
            };

            let display = display_certificate_chain(&chain, output_format)?;
            println!("{}", display);

            if let Some(out_path) = output {
                std::fs::write(&out_path, &display)?;
                println!("\n{}", format!("Saved to: {}", out_path.display()).green());
            }
        }

        Commands::Revoke {
            serial,
            reason,
            ca_cert,
            ca_key,
        } => {
            let algo = CertSigAlgo::EcdsaP256;
            let mut ca = CertificateAuthority::load_pem(ca_cert, ca_key, algo)?;

            let serial_bytes = decode_hex(&serial)?;

            let revocation_reason = match reason.to_lowercase().as_str() {
                "unspecified" => RevocationReason::Unspecified,
                "keycompromise" | "key-compromise" => RevocationReason::KeyCompromise,
                "cacompromise" | "ca-compromise" => RevocationReason::CACompromise,
                "affiliationchanged" | "affiliation-changed" => {
                    RevocationReason::AffiliationChanged
                }
                "superseded" => RevocationReason::Superseded,
                "cessationofoperation" | "cessation" => RevocationReason::CessationOfOperation,
                _ => {
                    return Err(crate::error::Error::InvalidInput(format!(
                        "Invalid revocation reason: {}",
                        reason
                    )))
                }
            };

            ca.revoke_certificate(serial_bytes, revocation_reason)?;

            println!("{}", "Certificate revoked successfully!".green().bold());
            println!("  {}: {}", "Serial".cyan(), serial);
            println!("  {}: {:?}", "Reason".cyan(), revocation_reason);
        }

        Commands::Crl {
            ca_cert,
            ca_key,
            output,
        } => {
            let algo = CertSigAlgo::EcdsaP256;
            let ca = CertificateAuthority::load_pem(ca_cert, ca_key, algo)?;

            let crl = ca.generate_crl()?;
            std::fs::write(&output, crl)?;

            println!("{}", "CRL generated successfully!".green().bold());
            println!("  {}: {}", "Output".cyan(), output.display());
            println!(
                "  {}: {}",
                "Revoked Certificates".cyan(),
                ca.revoked_certificates().len()
            );
        }

        Commands::Chain { cert_path } => {
            let cert_pem = std::fs::read_to_string(cert_path)?;
            println!("{}", "Certificate Chain".bold().cyan());
            println!("{}", "=".repeat(80));
            println!("{}", cert_pem);
        }
    }

    Ok(())
}

#[cfg(feature = "cli")]
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.replace([':', ' ', '-'], "");
    let mut result = Vec::new();

    for i in (0..s.len()).step_by(2) {
        if i + 1 >= s.len() {
            return Err(crate::error::Error::InvalidInput(
                "Invalid hex string".to_string(),
            ));
        }
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| crate::error::Error::InvalidInput("Invalid hex character".to_string()))?;
        result.push(byte);
    }

    Ok(result)
}

