pub mod error;
use self::error::Error;

pub mod response_builder;
pub mod sp_extractor;
pub mod verified_request;

#[cfg(test)]
mod tests;

use std::str::FromStr;

use crate::crypto::native::{PrivateKey, PrivateKeyOps};
use crate::crypto::{CertificateDer, Crypto, CryptoProvider};

use crate::idp::response_builder::{build_response_template, ResponseAttribute};
use crate::schema::Response;
use crate::traits::ToXml;

pub struct IdentityProvider {
    private_key: PrivateKey,
}

pub enum Rsa {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl Rsa {
    pub fn bit_length(&self) -> u32 {
        match &self {
            Rsa::Rsa2048 => 2048,
            Rsa::Rsa3072 => 3072,
            Rsa::Rsa4096 => 4096,
        }
    }
}

pub enum Elliptic {
    NISTP256,
}

pub enum KeyType {
    Rsa(Rsa),
    Elliptic(Elliptic),
}

pub struct CertificateParams<'a> {
    pub common_name: &'a str,
    pub issuer_name: &'a str,
    pub days_until_expiration: u32,
}

impl IdentityProvider {
    pub fn generate_new(key_type: KeyType) -> Result<Self, Error> {
        let private_key = PrivateKey::generate(key_type)?;
        Ok(IdentityProvider { private_key })
    }

    pub fn from_rsa_private_key_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let private_key = PrivateKey::from_rsa_der(der_bytes)?;
        Ok(IdentityProvider { private_key })
    }

    pub fn export_private_key_der(&self) -> Result<Vec<u8>, Error> {
        Ok(self.private_key.to_der()?)
    }

    pub fn create_certificate(&self, params: &CertificateParams) -> Result<CertificateDer, Error> {
        Ok(self.private_key.create_certificate(params)?)
    }

    pub fn sign_authn_response(
        &self,
        idp_x509_cert_der: &CertificateDer,
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

        let response_xml_unsigned = response.to_string()?;
        let signed_xml = Crypto::sign_xml(
            response_xml_unsigned.as_str(),
            self.export_private_key_der()?.as_slice(),
        )?;
        let signed_response = Response::from_str(signed_xml.as_str())?;
        Ok(signed_response)
    }
}
