mod cert_encoding;
mod crypto_disabled;
mod ids;
mod url_verification;
#[cfg(feature = "xmlsec")]
mod xmlsec;

use crate::schema::CipherValue;
pub use cert_encoding::*;
pub use ids::*;
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

/// Allowed XML signature algorithms for signature verification.
/// By default, all algorithms are allowed. Use this to restrict
/// signatures and reference digests to approved hash families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AllowedSignatureAlgorithm {
    /// RSA-SHA256 (required by most SAML profiles)
    RsaSha256,
    /// ECDSA-SHA256 (required by most SAML profiles)
    EcdsaSha256,
    /// RSA-SHA224
    RsaSha224,
    /// RSA-SHA384
    RsaSha384,
    /// RSA-SHA512
    RsaSha512,
    /// ECDSA-SHA224
    EcdsaSha224,
    /// ECDSA-SHA384
    EcdsaSha384,
    /// ECDSA-SHA512
    EcdsaSha512,
    /// DSA-SHA256
    DsaSha256,
}

impl AllowedSignatureAlgorithm {
    /// Returns the SignatureMethod URI as defined in XML Signature specifications.
    pub fn signature_uri(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::EcdsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            Self::RsaSha224 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
            Self::RsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            Self::RsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            Self::EcdsaSha224 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
            Self::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
            Self::DsaSha256 => "http://www.w3.org/2009/xmldsig11#dsa-sha256",
        }
    }

    /// Returns the DigestMethod URI required for signed references.
    pub fn digest_uri(&self) -> &'static str {
        match self {
            Self::RsaSha224 | Self::EcdsaSha224 => "http://www.w3.org/2001/04/xmldsig-more#sha224",
            Self::RsaSha256 | Self::EcdsaSha256 | Self::DsaSha256 => {
                "http://www.w3.org/2001/04/xmlenc#sha256"
            }
            Self::RsaSha384 | Self::EcdsaSha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
            Self::RsaSha512 | Self::EcdsaSha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
        }
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
    /// `ReduceMode::PreDigest` returns xmlsec's verified pre-digest payload for a single verified
    /// reference, or for the only verified SAML `Response` when several references are signed.
    /// The validate modes return a rooted XML document derived from the original input with all
    /// unsigned content removed.
    fn reduce_xml_to_signed(
        xml_str: &str,
        certs_der: &[CertificateDer],
        reduce_mode: ReduceMode,
    ) -> Result<String, CryptoError> {
        Self::reduce_xml_to_signed_with_allowed_algorithms(xml_str, certs_der, reduce_mode, None)
    }

    /// Takes an XML document, parses it, verifies all XML digital signatures against the given
    /// certificates, and returns output according to `reduce_mode`.
    ///
    /// If `allowed_algorithms` is `Some`, only the specified SignatureMethod algorithms
    /// and their corresponding DigestMethod algorithms will be accepted.
    /// If `None`, all algorithms are allowed.
    ///
    /// This provides protection against algorithm substitution attacks by enforcing signature
    /// algorithm restrictions at the xmlsec library level before any cryptographic operations.
    fn reduce_xml_to_signed_with_allowed_algorithms(
        xml_str: &str,
        certs_der: &[CertificateDer],
        reduce_mode: ReduceMode,
        allowed_algorithms: Option<&[AllowedSignatureAlgorithm]>,
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
