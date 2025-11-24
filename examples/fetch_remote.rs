use cutil::fetch::{display_certificate_chain, fetch_certificate_chain, OutputFormat};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let target = if args.len() > 1 {
        args[1].clone()
    } else {
        "google.com:443".to_string()
    };

    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        eprintln!("Usage: {} <host:port>", args[0]);
        eprintln!("Example: {} google.com:443", args[0]);
        std::process::exit(1);
    }

    let host = parts[0];
    let port: u16 = parts[1].parse()?;

    println!("Fetching certificate chain from {}:{}...\n", host, port);

    let chain = fetch_certificate_chain(host, port)?;

    let output = display_certificate_chain(&chain, OutputFormat::Pretty)?;
    println!("{}", output);

    println!("\nCertificate chain fetched successfully!");
    println!("Total certificates in chain: {}", chain.certificates.len());

    for (idx, cert) in chain.certificates.iter().enumerate() {
        println!("\nCertificate {}:", idx);
        println!("  Subject: {}", cert.subject);
        println!("  Valid: {}", cert.is_valid);
        println!("  Status: {}", cert.validity_status);
    }

    Ok(())
}
