//! Native (non-XML) crypto backend.
//!
//! This module abstracts the raw key, certificate and URL-signature operations
//! that samael needs, so they can be backed by either the OpenSSL crate or a
//! pure-Rust RustCrypto stack. Exactly one of the `openssl` / `rustcrypto`
//! features must be enabled (enforced in [`crate::crypto`]).
//!
//! XML digital signatures (sign/verify/decrypt of SAML documents) are handled
//! separately by the [`crate::crypto::CryptoProvider`] implementations and still
//! require `xmlsec`.

use crate::crypto::{CertificateDer, CryptoError};
use crate::idp::{CertificateParams, KeyType};
use crate::signature::SignatureAlgorithm;

#[cfg(feature = "openssl")]
mod openssl_backend;
#[cfg(feature = "openssl")]
pub use openssl_backend::{PrivateKey, PublicKey};

#[cfg(feature = "rustcrypto")]
mod rustcrypto_backend;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_backend::{PrivateKey, PublicKey};

/// Operations on a private signing key, regardless of backend.
pub trait PrivateKeyOps: Sized {
    /// Generate a fresh key pair of the requested type.
    fn generate(key_type: KeyType) -> Result<Self, CryptoError>;

    /// Load an RSA private key from DER (PKCS#1 or PKCS#8).
    fn from_rsa_der(der: &[u8]) -> Result<Self, CryptoError>;

    /// Export the private key as DER (PKCS#8 for RustCrypto, native DER for OpenSSL).
    fn to_der(&self) -> Result<Vec<u8>, CryptoError>;

    /// Whether this is an elliptic-curve (ECDSA) key, used to pick the SigAlg.
    fn is_ecdsa(&self) -> bool;

    /// Sign `data` with SHA-256 (RSA PKCS#1 v1.5 or ECDSA, per key type).
    fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Build a self-signed X.509 certificate for this key.
    fn create_certificate(&self, params: &CertificateParams) -> Result<CertificateDer, CryptoError>;
}

/// Operations on a public verification key, regardless of backend.
pub trait PublicKeyOps: Sized {
    fn from_rsa_pem(pem: &[u8]) -> Result<Self, CryptoError>;
    fn from_rsa_der(der: &[u8]) -> Result<Self, CryptoError>;
    fn from_ec_pem(pem: &[u8]) -> Result<Self, CryptoError>;
    fn from_ec_der(der: &[u8]) -> Result<Self, CryptoError>;
    fn from_x509_cert_pem(pem: &str) -> Result<Self, CryptoError>;
    fn from_x509_cert_der(cert: &CertificateDer) -> Result<Self, CryptoError>;

    /// Verify a SHA-256 signature produced by [`PrivateKeyOps::sign_sha256`].
    fn verify_sha256(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_alg: &SignatureAlgorithm,
    ) -> Result<bool, CryptoError>;
}
