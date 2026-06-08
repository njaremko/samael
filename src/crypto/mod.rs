#[cfg(not(any(feature = "openssl", feature = "rustcrypto")))]
compile_error!(
    "No native crypto backend is enabled. Enable exactly one of the `openssl` or `rustcrypto` features."
);

#[cfg(all(feature = "openssl", feature = "rustcrypto"))]
compile_error!(
    "The `openssl` and `rustcrypto` crypto backends are mutually exclusive; enable only one."
);

mod cert_encoding;
mod crypto_disabled;
mod ids;
pub mod native;
mod url_verification;
#[cfg(feature = "xmlsec")]
mod xmlsec;

use crate::schema::CipherValue;
pub use cert_encoding::*;
pub use ids::*;
pub use native::{PrivateKey, PublicKey};
use thiserror::Error;
pub use url_verification::{sign_url, UrlVerifier, UrlVerifierError};
#[cfg(feature = "xmlsec")]
pub use xmlsec::*;

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
    EncryptedAssertionKeyMethodUnsupported { method: String },

    #[error("The encryption method {method} is not supported for the assertion value")]
    EncryptedAssertionValueMethodUnsupported { method: String },

    #[error("The crypto provider is not enabled so encryption and signing methods are disabled")]
    CryptoDisabled,

    #[error("Crypto key error: {0}")]
    KeyError(String),
}

/// A certificate encoded in der format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDer(Vec<u8>);

impl CertificateDer {
    pub fn der_data(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for CertificateDer {
    fn from(cert_der: Vec<u8>) -> Self {
        Self(cert_der)
    }
}

/// Defines which algorithm is used to reduce signed XML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReduceMode {
    /// Returns xmlsec's pre-digest content for exactly one verified reference across the document.
    ///
    /// This is the strictest mode. It only works if there is one Signature element
    /// in the XML.
    PreDigest,
    /// Legacy mode that preserves the verified content and every element ancestor up to the
    /// document root.
    ///
    /// This is kept for compatibility with older callers. It is not recommended because unsigned
    /// ancestors can survive reduction in this mode.
    ValidateAndMark,
    /// Returns a rooted XML document containing only xmlsec-verified content.
    ///
    /// If the verified reference is a full element, that element becomes the output root. If the
    /// verified reference reduces to a child sequence, the referenced element is retained only as a
    /// stripped shell so the verified descendants remain rooted.
    ValidateAndMarkNoAncestors,
}

impl Default for ReduceMode {
    fn default() -> Self {
        Self::ValidateAndMarkNoAncestors
    }
}

pub trait CryptoProvider {
    type PrivateKey;

    fn verify_signed_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        x509_cert_der: &CertificateDer,
        id_attribute: Option<&str>,
    ) -> Result<(), CryptoError>;

    /// Takes an XML document, parses it, verifies all XML digital signatures against the given
    /// certificates, and returns output according to `reduce_mode`.
    ///
    /// `ReduceMode::PreDigest` returns xmlsec's verified pre-digest payload for exactly one
    /// reference. The validate modes return a rooted XML document derived from the original input
    /// with all unsigned content removed.
    fn reduce_xml_to_signed(
        xml_str: &str,
        certs_der: &[CertificateDer],
        reduce_mode: ReduceMode,
    ) -> Result<String, CryptoError>;

    fn decrypt_assertion_key_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &Self::PrivateKey,
    ) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_assertion_value_info(
        cipher_value: &CipherValue,
        method: &str,
        decryption_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn sign_xml<Bytes: AsRef<[u8]>>(
        xml: Bytes,
        private_key_der: &[u8],
    ) -> Result<String, CryptoError>;
}
