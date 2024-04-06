use std::str::FromStr;
use std::time::Duration;
use sha2::Sha256;
use rsa::pkcs1v15::SigningKey;
use x509_cert::{
    der::{Decode, Encode},
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
    time::Validity
};

use super::CertificateLike;
use crate::idp::CertificateParams;
use crate::crypto::rsa::PublicKeyLike;
pub use x509_cert::Certificate;
use x509_cert::der::DecodePem;

impl<'a> CertificateLike<crate::crypto::rsa::PrivateKey> for Certificate {
    fn new(
        private_key: &crate::crypto::rsa::PrivateKey,
        params: &CertificateParams,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create a new certificate
        let profile = Profile::Root;
        let serial_number = SerialNumber::from(rand::random::<u8>());
        let validity = Validity::from_now(Duration::from_secs((params.days_until_expiration / 24 / 60 / 60) as u64)).unwrap();
        let subject = Name::from_str(format!("CN={},O={},C={}", params.common_name,params.issuer_name,params.issuer_country_code).as_str()).unwrap();
        let public_key_der = private_key.to_public_key().to_der().unwrap();
        let public_key = SubjectPublicKeyInfoOwned::from_der(&public_key_der).unwrap();
        let signer = SigningKey::<Sha256>::new(private_key.clone());
        let builder = CertificateBuilder::new(profile,serial_number,validity,subject,public_key).unwrap();
        Ok(builder.build(&signer).unwrap())
    }

    fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(Encode::to_der(self)?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<(dyn std::error::Error)>> {
        Ok(Decode::from_der(der)?)
    }

    fn public_key(&self) -> &[u8] {
        self.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()
    }

    fn from_pem(pem: &[u8]) -> Result<Self, Box<(dyn std::error::Error)>> {
        Ok(DecodePem::from_pem(pem)?)
    }

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(Encode::to_der(self)?)
    }
}