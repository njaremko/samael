//! Pure-Rust (RustCrypto) implementation of the native crypto backend.
//!
//! Supports RSA (PKCS#1 v1.5 + SHA-256) and ECDSA P-256 (SHA-256) for key
//! generation, signing/verification, and self-signed X.509 certificate
//! generation. No OpenSSL / C dependency is involved.

use std::str::FromStr;
use std::time::Duration;

use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::{SignatureEncoding, Signer, Verifier};

use p256::ecdsa::{
    DerSignature as EcDerSignature, Signature as EcSignature, SigningKey as EcSigningKey,
    VerifyingKey as EcVerifyingKey,
};
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::Encode;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::Validity;
use x509_cert::TbsCertificate;

use super::{PrivateKeyOps, PublicKeyOps};
use crate::crypto::{CertificateDer, CryptoError};
use crate::idp::{CertificateParams, Elliptic, KeyType};
use crate::signature::SignatureAlgorithm;

fn err<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::KeyError(e.to_string())
}

/// An OS-backed cryptographically secure RNG implementing the `rand_core` 0.10
/// traits. `rand_core` 0.10 no longer ships an `OsRng`, so we provide a thin
/// wrapper over `getrandom`. (`Rng` and `CryptoRng` come from blanket impls.)
struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_ne_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_ne_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(dst).expect("operating system RNG failure");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

/// A private signing key backed by RustCrypto.
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ecdsa(Box<EcSigningKey>),
}

/// A public verification key backed by RustCrypto.
pub enum PublicKey {
    Rsa(Box<RsaPublicKey>),
    Ecdsa(Box<EcVerifyingKey>),
}

impl PrivateKeyOps for PrivateKey {
    fn generate(key_type: KeyType) -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        match key_type {
            KeyType::Rsa(rsa) => {
                let key = RsaPrivateKey::new(&mut rng, rsa.bit_length() as usize).map_err(err)?;
                Ok(PrivateKey::Rsa(key))
            }
            KeyType::Elliptic(Elliptic::NISTP256) => {
                let key = EcSigningKey::random(&mut rng);
                Ok(PrivateKey::Ecdsa(Box::new(key)))
            }
        }
    }

    fn from_rsa_der(der: &[u8]) -> Result<Self, CryptoError> {
        let key = RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(der))
            .map_err(err)?;
        Ok(PrivateKey::Rsa(key))
    }

    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            PrivateKey::Rsa(key) => Ok(key.to_pkcs8_der().map_err(err)?.as_bytes().to_vec()),
            PrivateKey::Ecdsa(key) => Ok(key.to_pkcs8_der().map_err(err)?.as_bytes().to_vec()),
        }
    }

    fn is_ecdsa(&self) -> bool {
        matches!(self, PrivateKey::Ecdsa(_))
    }

    fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            PrivateKey::Rsa(key) => {
                let signing_key = RsaSigningKey::<Sha256>::new(key.clone());
                let signature: RsaSignature = signing_key.try_sign(data).map_err(err)?;
                Ok(signature.to_vec())
            }
            PrivateKey::Ecdsa(key) => {
                // Match OpenSSL, which produces DER-encoded ECDSA signatures.
                let signature: EcSignature = key.try_sign(data).map_err(err)?;
                Ok(signature.to_der().to_vec())
            }
        }
    }

    fn create_certificate(&self, params: &CertificateParams) -> Result<CertificateDer, CryptoError> {
        let profile = SelfSignedProfile::new(params)?;
        let serial = SerialNumber::from(rand_serial());
        let validity = Validity::from_now(Duration::from_secs(
            params.days_until_expiration as u64 * 24 * 60 * 60,
        ))
        .map_err(err)?;

        let der = match self {
            PrivateKey::Rsa(key) => {
                let signing_key = RsaSigningKey::<Sha256>::new(key.clone());
                let spki = SubjectPublicKeyInfoOwned::from_key(&RsaPublicKey::from(key)).map_err(err)?;
                let builder = CertificateBuilder::new(profile, serial, validity, spki).map_err(err)?;
                let cert = builder.build::<_, RsaSignature>(&signing_key).map_err(err)?;
                cert.to_der().map_err(err)?
            }
            PrivateKey::Ecdsa(key) => {
                let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).map_err(err)?;
                let builder = CertificateBuilder::new(profile, serial, validity, spki).map_err(err)?;
                let cert = builder.build::<_, EcDerSignature>(key.as_ref()).map_err(err)?;
                cert.to_der().map_err(err)?
            }
        };
        Ok(der.into())
    }
}

impl PublicKeyOps for PublicKey {
    fn from_rsa_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let pem = std::str::from_utf8(pem).map_err(err)?;
        let key = RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem))
            .map_err(err)?;
        Ok(PublicKey::Rsa(Box::new(key)))
    }

    fn from_rsa_der(der: &[u8]) -> Result<Self, CryptoError> {
        let key = RsaPublicKey::from_public_key_der(der)
            .or_else(|_| RsaPublicKey::from_pkcs1_der(der))
            .map_err(err)?;
        Ok(PublicKey::Rsa(Box::new(key)))
    }

    fn from_ec_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let pem = std::str::from_utf8(pem).map_err(err)?;
        let key = EcVerifyingKey::from_public_key_pem(pem).map_err(err)?;
        Ok(PublicKey::Ecdsa(Box::new(key)))
    }

    fn from_ec_der(der: &[u8]) -> Result<Self, CryptoError> {
        let key = EcVerifyingKey::from_public_key_der(der).map_err(err)?;
        Ok(PublicKey::Ecdsa(Box::new(key)))
    }

    fn from_x509_cert_pem(pem: &str) -> Result<Self, CryptoError> {
        use x509_cert::der::DecodePem;
        let cert = x509_cert::Certificate::from_pem(pem).map_err(err)?;
        Self::from_cert_spki(&cert)
    }

    fn from_x509_cert_der(cert: &CertificateDer) -> Result<Self, CryptoError> {
        use x509_cert::der::Decode;
        let cert = x509_cert::Certificate::from_der(cert.der_data()).map_err(err)?;
        Self::from_cert_spki(&cert)
    }

    fn verify_sha256(
        &self,
        data: &[u8],
        signature: &[u8],
        _sig_alg: &SignatureAlgorithm,
    ) -> Result<bool, CryptoError> {
        match self {
            PublicKey::Rsa(key) => {
                let verifying_key = RsaVerifyingKey::<Sha256>::new((**key).clone());
                let signature = RsaSignature::try_from(signature).map_err(err)?;
                Ok(verifying_key.verify(data, &signature).is_ok())
            }
            PublicKey::Ecdsa(key) => {
                let signature = EcSignature::from_der(signature).map_err(err)?;
                Ok(key.verify(data, &signature).is_ok())
            }
        }
    }
}

impl PublicKey {
    /// Build a verification key from a parsed certificate's SubjectPublicKeyInfo,
    /// dispatching on the public-key algorithm.
    fn from_cert_spki(cert: &x509_cert::Certificate) -> Result<Self, CryptoError> {
        use x509_cert::der::referenced::OwnedToRef;
        let spki = cert
            .tbs_certificate()
            .subject_public_key_info()
            .owned_to_ref();
        // Try RSA, then EC P-256.
        if let Ok(key) = RsaPublicKey::try_from(spki.clone()) {
            return Ok(PublicKey::Rsa(Box::new(key)));
        }
        let key = EcVerifyingKey::try_from(spki)
            .map_err(|_| CryptoError::KeyError("unsupported certificate public key".into()))?;
        Ok(PublicKey::Ecdsa(Box::new(key)))
    }
}

/// Random serial number for generated certificates.
fn rand_serial() -> u64 {
    let mut buf = [0u8; 8];
    // Best effort; fall back to a fixed value if the OS RNG is unavailable.
    if getrandom::fill(&mut buf).is_err() {
        return 1;
    }
    // Keep it positive and non-zero for a valid DER INTEGER serial.
    (u64::from_be_bytes(buf) >> 1) | 1
}

/// Minimal X.509 profile for a self-signed certificate with the given subject
/// and issuer common names and no extensions.
struct SelfSignedProfile {
    subject: Name,
    issuer: Name,
}

impl SelfSignedProfile {
    fn new(params: &CertificateParams) -> Result<Self, CryptoError> {
        Ok(Self {
            subject: Name::from_str(&format!("CN={}", params.common_name)).map_err(err)?,
            issuer: Name::from_str(&format!("CN={}", params.issuer_name)).map_err(err)?,
        })
    }
}

impl BuilderProfile for SelfSignedProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> Result<Vec<Extension>, x509_cert::builder::Error> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::idp::{CertificateParams, Elliptic, KeyType, Rsa};

    /// Generate a key, self-sign a certificate, then recover the public key from
    /// that certificate and verify a signature made with the private key. This
    /// exercises key generation, signing, the X.509 builder, certificate
    /// parsing, and verification end-to-end in pure Rust.
    fn keygen_cert_sign_verify(key_type: KeyType) {
        let key = PrivateKey::generate(key_type).expect("key generation");
        let alg = if key.is_ecdsa() {
            SignatureAlgorithm::EcdsaSha256
        } else {
            SignatureAlgorithm::RsaSha256
        };

        let data = b"SAMLRequest=abc&RelayState=xyz&SigAlg=def";
        let signature = key.sign_sha256(data).expect("sign");

        let params = CertificateParams {
            common_name: "https://idp.example.com",
            issuer_name: "https://idp.example.com",
            days_until_expiration: 365,
        };
        let cert = key.create_certificate(&params).expect("create certificate");

        let public_key = PublicKey::from_x509_cert_der(&cert).expect("parse certificate");
        assert!(public_key
            .verify_sha256(data, &signature, &alg)
            .expect("verify"));

        // A tampered payload must not verify.
        assert!(!public_key
            .verify_sha256(b"tampered", &signature, &alg)
            .expect("verify"));
    }

    #[test]
    fn rsa_keygen_cert_sign_verify() {
        keygen_cert_sign_verify(KeyType::Rsa(Rsa::Rsa2048));
    }

    #[test]
    fn ecdsa_keygen_cert_sign_verify() {
        keygen_cert_sign_verify(KeyType::Elliptic(Elliptic::NISTP256));
    }
}
