pub mod error;
use self::error::Error;

pub mod response_builder;
pub mod sp_extractor;
pub mod verified_request;

#[cfg(test)]
mod tests;

use crate::crypto::rsa::{PrivateKey, PrivateKeyLike};
#[cfg(feature = "xmlsec")]
use crate::crypto;

use crate::crypto::x509::{Certificate, CertificateLike};
use crate::crypto::x509;


#[cfg(feature = "xmlsec")]
use crate::schema::Response;
#[cfg(feature = "xmlsec")]
use crate::traits::ToXml;
#[cfg(feature = "xmlsec")]
use crate::idp::response_builder::{build_response_template, ResponseAttribute};
#[cfg(feature = "xmlsec")]
use std::str::FromStr;


pub struct IdentityProvider<PrivateKey>
    where
        PrivateKey: PrivateKeyLike,
{
    private_key: PrivateKey,
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
    pub issuer_country_code: &'a str,
    pub days_until_expiration: u32,
}

impl IdentityProvider<PrivateKey> {
    pub fn generate_new(key_type: KeyType) -> Result<Self, Error> {
        let private_key = PrivateKeyLike::new(usize::try_from(key_type.bit_length()).unwrap()).unwrap();
        Ok(IdentityProvider { private_key })
    }

    pub fn from_private_key_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let private_key = PrivateKey::from_der(der_bytes).unwrap();
        Ok(IdentityProvider { private_key })
    }

    pub fn export_private_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.private_key.to_der().unwrap())
    }

    pub fn create_certificate(&self, params: &CertificateParams) -> Result<Vec<u8>, Error> {
        let cert = x509::Certificate::new(&self.private_key, params).unwrap();
        Ok(cert.to_vec().unwrap())
    }

    #[cfg(feature = "xmlsec")]
    pub fn sign_authn_response(
        &self,
        idp_x509_cert_der: &[u8],
        subject_name_id: &str,
        audience: &str,
        acs_url: &str,
        issuer: &str,
        in_response_to_id: &str,
        attributes: &[ResponseAttribute],
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let response = build_response_template(
            idp_x509_cert_der,
            subject_name_id,
            audience,
            issuer,
            acs_url,
            in_response_to_id,
            attributes,
        );

        let response_xml_unsigned = response.to_xml()?;
        let signed_xml = crypto::sign_xml(
            response_xml_unsigned.as_str(),
            self.export_private_key_der()?.as_slice(),
        )?;
        let signed_response = Response::from_str(signed_xml.as_str())?;
        Ok(signed_response)
    }
}
