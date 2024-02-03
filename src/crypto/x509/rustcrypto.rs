use std::str::FromStr;
use std::time::Duration;
use sha2::Sha256;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use rsa::pkcs1v15::SigningKey;
use x509_cert::der::{Decode, Encode};

use super::CertificateLike;
use crate::idp::CertificateParams;
pub use x509_cert::Certificate;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use crate::crypto::rsa::PublicKeyLike;

impl<'a> CertificateLike<crate::crypto::rsa::PrivateKey> for Certificate {
    fn new(
        private_key: &crate::crypto::rsa::PrivateKey,
        params: &CertificateParams,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Create a new certificate
        let profile = Profile::Root;
        let serial_number = SerialNumber::from(rand::random::<u8>());
        let mut validity = Validity::from_now(Duration::from_secs((params.days_until_expiration / 24 / 60 / 60) as u64)).unwrap();
        let subject = Name::from_str(format!("CN={},O={},C={}", params.common_name,params.issuer_name,params.issuer_country_code).as_str()).unwrap();
        let public_key_der = private_key.to_public_key().to_der().unwrap();
        let public_key = SubjectPublicKeyInfoOwned::from_der(&public_key_der).unwrap();
        let mut signer = SigningKey::<Sha256>::new(private_key.clone());
        let mut builder = CertificateBuilder::new(profile,serial_number,validity,subject,public_key,&signer).unwrap();
        Ok(builder.build().unwrap())
    }

    fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(Encode::to_vec(self)?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<(dyn std::error::Error)>> {
        Ok(Decode::from_der(der)?)
    }

    fn public_key(&self) -> &[u8] {
        self.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()
    }
}