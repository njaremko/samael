//! OpenSSL implementation of the native crypto backend.

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::x509;

use super::{PrivateKeyOps, PublicKeyOps};
use crate::crypto::{CertificateDer, CryptoError};
use crate::idp::{CertificateParams, Elliptic, KeyType};
use crate::signature::SignatureAlgorithm;

pub type PrivateKey = PKey<Private>;
pub type PublicKey = PKey<Public>;

fn err<E: std::fmt::Display>(e: E) -> CryptoError {
    CryptoError::KeyError(e.to_string())
}

impl PrivateKeyOps for PrivateKey {
    fn generate(key_type: KeyType) -> Result<Self, CryptoError> {
        match key_type {
            KeyType::Rsa(rsa) => {
                let rsa = openssl::rsa::Rsa::generate(rsa.bit_length()).map_err(err)?;
                PKey::from_rsa(rsa).map_err(err)
            }
            KeyType::Elliptic(ecc) => {
                let nid = match ecc {
                    Elliptic::NISTP256 => Nid::X9_62_PRIME256V1,
                };
                let group = EcGroup::from_curve_name(nid).map_err(err)?;
                let private_key: EcKey<Private> = EcKey::generate(&group).map_err(err)?;
                PKey::from_ec_key(private_key).map_err(err)
            }
        }
    }

    fn from_rsa_der(der: &[u8]) -> Result<Self, CryptoError> {
        let rsa = openssl::rsa::Rsa::private_key_from_der(der).map_err(err)?;
        PKey::from_rsa(rsa).map_err(err)
    }

    fn to_der(&self) -> Result<Vec<u8>, CryptoError> {
        if let Ok(ec_key) = self.ec_key() {
            ec_key.private_key_to_der().map_err(err)
        } else if let Ok(rsa) = self.rsa() {
            rsa.private_key_to_der().map_err(err)
        } else {
            Err(CryptoError::KeyError("unexpected private key type".into()))
        }
    }

    fn is_ecdsa(&self) -> bool {
        self.ec_key().is_ok()
    }

    fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signer = Signer::new(MessageDigest::sha256(), self).map_err(err)?;
        signer.update(data).map_err(err)?;
        signer.sign_to_vec().map_err(err)
    }

    fn create_certificate(&self, params: &CertificateParams) -> Result<CertificateDer, CryptoError> {
        let mut name = x509::X509Name::builder().map_err(err)?;
        name.append_entry_by_nid(Nid::COMMONNAME, params.common_name)
            .map_err(err)?;
        let name = name.build();

        let mut iss = x509::X509Name::builder().map_err(err)?;
        iss.append_entry_by_nid(Nid::COMMONNAME, params.issuer_name)
            .map_err(err)?;
        let iss = iss.build();

        let mut builder = x509::X509::builder().map_err(err)?;

        let serial_number = {
            let mut serial = BigNum::new().map_err(err)?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false).map_err(err)?;
            serial.to_asn1_integer().map_err(err)?
        };

        builder.set_serial_number(&serial_number).map_err(err)?;
        builder.set_version(2).map_err(err)?;
        builder.set_subject_name(&name).map_err(err)?;
        builder.set_issuer_name(&iss).map_err(err)?;
        builder.set_pubkey(self).map_err(err)?;

        let starts = Asn1Time::days_from_now(0).map_err(err)?; // now
        builder.set_not_before(&starts).map_err(err)?;

        let expires = Asn1Time::days_from_now(params.days_until_expiration).map_err(err)?;
        builder.set_not_after(&expires).map_err(err)?;

        builder.sign(self, MessageDigest::sha256()).map_err(err)?;

        let certificate: x509::X509 = builder.build();
        Ok(certificate.to_der().map_err(err)?.into())
    }
}

impl PublicKeyOps for PublicKey {
    fn from_rsa_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let public = openssl::rsa::Rsa::public_key_from_pem(pem).map_err(err)?;
        PKey::from_rsa(public).map_err(err)
    }

    fn from_rsa_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public = openssl::rsa::Rsa::public_key_from_der(der).map_err(err)?;
        PKey::from_rsa(public).map_err(err)
    }

    fn from_ec_pem(pem: &[u8]) -> Result<Self, CryptoError> {
        let public = EcKey::public_key_from_pem(pem).map_err(err)?;
        PKey::from_ec_key(public).map_err(err)
    }

    fn from_ec_der(der: &[u8]) -> Result<Self, CryptoError> {
        let public = EcKey::public_key_from_der(der).map_err(err)?;
        PKey::from_ec_key(public).map_err(err)
    }

    fn from_x509_cert_pem(pem: &str) -> Result<Self, CryptoError> {
        let x509 = x509::X509::from_pem(pem.as_bytes()).map_err(err)?;
        x509.public_key().map_err(err)
    }

    fn from_x509_cert_der(cert: &CertificateDer) -> Result<Self, CryptoError> {
        let x509 = x509::X509::from_der(cert.der_data()).map_err(err)?;
        x509.public_key().map_err(err)
    }

    fn verify_sha256(
        &self,
        data: &[u8],
        signature: &[u8],
        _sig_alg: &SignatureAlgorithm,
    ) -> Result<bool, CryptoError> {
        // OpenSSL's Verifier derives the algorithm from the key type; both
        // RSA-SHA256 and ECDSA-SHA256 use a SHA-256 digest.
        let mut verifier = Verifier::new(MessageDigest::sha256(), self).map_err(err)?;
        verifier.update(data).map_err(err)?;
        verifier.verify(signature).map_err(err)
    }
}
