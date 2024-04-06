use std::error::Error;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey};
use openssl::x509::{X509Name as Name, X509};
pub use openssl::x509::X509 as Certificate;

use crate::crypto::rsa;
use crate::idp::CertificateParams;

use crate::crypto::x509::CertificateLike;

impl<Key: rsa::PrivateKeyLike> CertificateLike<Key> for Certificate {
    fn new(
        private_key: &Key,
        params: &CertificateParams,
    ) -> Result<Self, Box<dyn Error>> {
        let mut name = Name::builder()?;
        name.append_entry_by_nid(Nid::COMMONNAME, params.common_name)?;
        let name = name.build();

        let mut iss = Name::builder()?;
        iss.append_entry_by_nid(Nid::COMMONNAME, params.issuer_name)?;
        let iss = iss.build();

        let mut builder = X509::builder()?;

        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };


        builder.set_serial_number(&serial_number)?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&iss)?;
        let pk = PKey::private_key_from_der(private_key.to_der().unwrap().as_slice())?;
        builder.set_pubkey(&pk)?;

        let starts = Asn1Time::days_from_now(0)?; // now
        builder.set_not_before(&starts)?;

        let expires = Asn1Time::days_from_now(params.days_until_expiration)?;
        builder.set_not_after(&expires)?;

        builder.sign(&pk, MessageDigest::sha256())?;
        Ok(builder.build())
    }

    fn to_vec(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.as_ref().to_der()?)
    }

    fn from_der(der: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(X509::from_der(der)?)
    }

    fn public_key(&self) -> &[u8] {
        self.as_ref().public_key().unwrap().public_key_to_der().unwrap().as_slice()
    }

    fn from_pem(pem: &[u8]) -> Result<Self, Box<(dyn Error)>> {
        Ok(X509::from_pem(pem)?)
    }

    fn to_der(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.as_ref().to_der()?)
    }
}