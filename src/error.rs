use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Certificate generation error: {0}")]
    CertGen(String),

    #[error("Certificate parsing error: {0}")]
    CertParse(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Certificate not found: {0}")]
    NotFound(String),

    #[error("Certificate already revoked: serial {0}")]
    AlreadyRevoked(String),

    #[error("Invalid certificate chain: {0}")]
    InvalidChain(String),

    #[error("PKCS12 export error: {0}")]
    Pkcs12(String),

    #[error("PEM parsing error: {0}")]
    Pem(String),

    #[error("X509 parsing error: {0}")]
    X509Parse(String),

    #[error("DER encoding error: {0}")]
    DerEncode(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("DNS name error: {0}")]
    DnsName(String),

    #[error("Certificate expired or not yet valid")]
    CertExpired,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<rcgen::Error> for Error {
    fn from(err: rcgen::Error) -> Self {
        Error::CertGen(err.to_string())
    }
}

impl From<rustls::Error> for Error {
    fn from(err: rustls::Error) -> Self {
        Error::Tls(err.to_string())
    }
}

impl From<x509_parser::error::X509Error> for Error {
    fn from(err: x509_parser::error::X509Error) -> Self {
        Error::X509Parse(err.to_string())
    }
}

impl From<x509_parser::nom::Err<x509_parser::error::X509Error>> for Error {
    fn from(err: x509_parser::nom::Err<x509_parser::error::X509Error>) -> Self {
        Error::X509Parse(err.to_string())
    }
}

impl From<der_parser::error::Error> for Error {
    fn from(err: der_parser::error::Error) -> Self {
        Error::DerEncode(err.to_string())
    }
}

impl From<yasna::ASN1Error> for Error {
    fn from(err: yasna::ASN1Error) -> Self {
        Error::DerEncode(err.to_string())
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serialization(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
