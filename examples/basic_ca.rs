use cutil::ca::CertificateAuthority;
use cutil::cert::CertificateBuilder;
use cutil::types::{CertSigAlgo, DistinguishedName};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating a Root CA...");

    let ca_subject = DistinguishedName::new("Example Root CA")
        .with_organization("Example Organization")
        .with_organizational_unit("IT Security")
        .with_country("US")
        .with_state("California")
        .with_locality("San Francisco");

    let mut ca = CertificateAuthority::new_root(ca_subject, CertSigAlgo::EcdsaP256, 3650)?;

    ca.save_pem("example-ca.pem", "example-ca-key.pem")?;
    println!("Root CA created and saved!");

    println!("\nIssuing a server certificate...");

    let server_cert = CertificateBuilder::server("example.com")
        .with_dns_san("example.com")
        .with_dns_san("www.example.com")
        .with_dns_san("api.example.com")
        .with_validity_days(365)
        .issue(&mut ca)?;

    server_cert.save_pem("server.pem", "server-key.pem")?;
    server_cert.save_chain("server-chain.pem")?;
    println!("Server certificate issued!");

    println!("\nIssuing a client certificate...");

    let client_cert = CertificateBuilder::client("Alice Smith")
        .with_email_san("alice@example.com")
        .with_validity_days(365)
        .issue(&mut ca)?;

    client_cert.save_pem("client.pem", "client-key.pem")?;
    println!("Client certificate issued!");

    println!("\nExporting client certificate as PKCS#12...");
    let p12_data = client_cert.export_pkcs12("password123", "Alice Smith")?;
    std::fs::write("client.p12", p12_data)?;
    println!("Client certificate exported as PKCS#12!");

    println!("\nAll certificates created successfully!");
    println!("Files created:");
    println!("  - example-ca.pem (Root CA certificate)");
    println!("  - example-ca-key.pem (Root CA private key)");
    println!("  - server.pem (Server certificate)");
    println!("  - server-key.pem (Server private key)");
    println!("  - server-chain.pem (Server certificate chain)");
    println!("  - client.pem (Client certificate)");
    println!("  - client-key.pem (Client private key)");
    println!("  - client.p12 (Client PKCS#12 bundle)");

    Ok(())
}
