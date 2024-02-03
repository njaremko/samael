use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::{X509Name as Name, X509};

use crate::crypto::rsa;
use crate::idp::CertificateParams;

use crate::crypto::x509::CertificateLike;

impl<Key: rsa::PrivateKeyLike> CertificateLike<Key> for X509 {
    fn new(
        private_key: &Key,
        params: &CertificateParams,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
        builder.set_pubkey(&private_key)?;

        let starts = Asn1Time::days_from_now(0)?; // now
        builder.set_not_before(&starts)?;

        let expires = Asn1Time::days_from_now(params.days_until_expiration)?;
        builder.set_not_after(&expires)?;

        builder.sign(&self.private_key.0, MessageDigest::sha256())?;

        Ok(Self(builder.build()?))
    }

    fn to_vec(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        self.0.to_der()
    }

    fn public_key(&self) -> &[u8] {
        self.0.public_key()
    }
}