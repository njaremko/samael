#[cfg(feature = "xmlsec")]
mod xmlsec;
mod cert_encoding;
mod url_verification;
mod ids;
mod crypto_disabled;

pub use cert_encoding::*;
#[cfg(feature = "xmlsec")]
pub use xmlsec::*;
pub use ids::*;
pub use url_verification::{UrlVerifier, UrlVerifierError};
use thiserror::Error;
use crate::schema::{CipherValue};

#[cfg(feature = "xmlsec")]
pub type Crypto = XmlSec;
#[cfg(not(feature = "xmlsec"))]
pub type Crypto = crypto_disabled::NoCrypto;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encountered an invalid signature")]
    InvalidSignature,

    #[error("base64 decoding Error: {}", error)]
    Base64Error {
        #[from]
        error: base64::DecodeError,
    },

    #[error("The given XML is missing a root element")]
    XmlMissingRootElement,

    #[error("Crypto Provider Error")]
    CryptoProviderError(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("The encryption method {method} is not supported for the assertion key")]
EncryptedAssertionKeyMethodUnsupported {
method: String
},


    #[error("The encryption method {method} is not supported for the assertion value")]
    EncryptedAssertionValueMethodUnsupported {
        method: String
    },
    
    #[error("The crypto provider is not enabled so encryption and signing methods are disabled")]
    CryptoDisabled,
}

pub trait CryptoProvider {
    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        x509_cert_der: &[u8],
        id_attribute: Option<&str>) -> Result<(), CryptoError>;

    fn decrypt_assertion_key_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_assertion_value_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn sign_xml<Bytes: AsRef<[u8]>>(xml: Bytes, private_key_der: &[u8]) -> Result<String, CryptoError>;
}