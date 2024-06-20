pub mod error;
use self::error::Error;

mod authentication_context_class;
pub mod response_builder;
pub mod sp_extractor;
pub mod verified_request;
pub use authentication_context_class::*;

#[cfg(test)]
mod tests;

use openssl::bn::{BigNum, MsbOption};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::{asn1::Asn1Time, pkey, rsa::Rsa, x509};
use std::str::FromStr;

use crate::crypto::{self};

use crate::idp::response_builder::{build_response_template, ResponseAttribute};
use crate::schema::Response;
use crate::traits::ToXml;
use chrono::{DateTime, Utc};

pub struct IdentityProvider {
    private_key: pkey::PKey<Private>,
}

pub enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl KeyType {
    fn bit_length(&self) -> u32 {
        match &self {
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
        }
    }
}

pub struct CertificateParams<'a> {
    pub common_name: &'a str,
    pub issuer_name: &'a str,
    pub days_until_expiration: u32,
}

pub struct ResponseParams<'a> {
    pub idp_x509_cert_der: &'a [u8],
    pub subject_name_id: &'a str,
    pub audience: &'a str,
    pub acs_url: &'a str,
    pub issuer: &'a str,
    pub in_response_to_id: &'a str,
    pub attributes: &'a [ResponseAttribute],
    pub authentication_context: AuthenticationContextClass,
    pub not_before: Option<DateTime<Utc>>,
    pub not_on_or_after: Option<DateTime<Utc>>,
}

impl IdentityProvider {
    pub fn generate_new(key_type: KeyType) -> Result<Self, Error> {
        let rsa = Rsa::generate(key_type.bit_length())?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider { private_key })
    }

    pub fn from_private_key_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let rsa = Rsa::private_key_from_der(der_bytes)?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider { private_key })
    }

    pub fn export_private_key_der(&self) -> Result<Vec<u8>, Error> {
        let rsa: Rsa<Private> = self.private_key.rsa()?;
        Ok(rsa.private_key_to_der()?)
    }

    pub fn create_certificate(&self, params: &CertificateParams) -> Result<Vec<u8>, Error> {
        let mut name = x509::X509Name::builder()?;
        name.append_entry_by_nid(Nid::COMMONNAME, params.common_name)?;
        let name = name.build();

        let mut iss = x509::X509Name::builder()?;
        iss.append_entry_by_nid(Nid::COMMONNAME, params.issuer_name)?;
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

        let expires = Asn1Time::days_from_now(params.days_until_expiration)?;
        builder.set_not_after(&expires)?;

        builder.sign(&self.private_key, openssl::hash::MessageDigest::sha256())?;

        let certificate: x509::X509 = builder.build();
        Ok(certificate.to_der()?)
    }

    pub fn sign_authn_response(
        &self,
        params: &ResponseParams,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let response = build_response_template(params);

        let response_xml_unsigned = response.to_xml()?;
        let signed_xml = crypto::sign_xml(
            response_xml_unsigned.as_str(),
            self.export_private_key_der()?.as_slice(),
        )?;
        let signed_response = Response::from_str(signed_xml.as_str())?;
        Ok(signed_response)
    }
}
