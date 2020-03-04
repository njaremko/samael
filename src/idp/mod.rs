pub mod error;
use self::error::Error;

pub mod sp_extractor;
pub mod verified_request;
pub mod response_builder;

#[cfg(test)]
mod tests;

use std::str::FromStr;
use openssl::{rsa::Rsa, x509, pkey, asn1::Asn1Time};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::bn::{BigNum, MsbOption};

use crate::crypto::{self};

use crate::schema::Response;
use crate::idp::response_builder::{build_response_template};
use response_builder::ResponseAttribute;

pub struct IdentityProvider {
    private_key: pkey::PKey<Private>,
}

impl IdentityProvider {
    pub fn generate_new() -> Result<Self, Error> {
        let rsa = Rsa::generate(3072)?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider {
            private_key,
        })
    }

    pub fn from_private_key_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let rsa = Rsa::private_key_from_der(der_bytes)?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider {
            private_key,
        })
    }

    pub fn export_private_key_der(&self) -> Result<Vec<u8>, Error> {
        let rsa: Rsa<Private> = self.private_key.rsa()?;
        Ok(rsa.private_key_to_der()?)
    }

    pub fn create_certificate(&self, common_name: &str, _issuer_name: &str) -> Result<Vec<u8>, Error> {
        let mut name = x509::X509Name::builder()?;
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
        let name = name.build();

        let mut iss = x509::X509Name::builder()?;
        iss.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
        let iss = iss.build();

        let mut builder = x509::X509::builder()?;

        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };

        builder.set_serial_number(&serial_number)?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&iss)?;
        builder.set_pubkey(&self.private_key)?;

        let starts = Asn1Time::days_from_now(0)?; // now
        builder.set_not_before(&starts)?;

        let expires = Asn1Time::days_from_now(3650)?; // 10 years
        builder.set_not_after(&expires)?;

        builder.sign(&self.private_key, openssl::hash::MessageDigest::sha256())?;

        let certificate: x509::X509 = builder.build();
        Ok(certificate.to_der()?)
    }

    pub fn sign_authn_response(&self,
                               idp_x509_cert_der: &[u8],
                               subject_name_id: &str,
                               audience: &str,
                               acs_url: &str,
                               issuer: &str,
                               in_response_to_id: &str,
                               attributes: &[ResponseAttribute]) -> Result<Response, Box<dyn std::error::Error>>
    {
        let response = build_response_template(idp_x509_cert_der,
                                               subject_name_id,
                                               audience,
                                               issuer,
                                               acs_url,
                                               in_response_to_id,
                                               attributes);

        let response_xml_unsigned = response.to_xml()?;
        let signed_xml = crypto::sign_xml(response_xml_unsigned.as_str(), self.export_private_key_der()?.as_slice())?;
        let signed_response = Response::from_str(signed_xml.as_str())?;
        Ok(signed_response)
    }
}