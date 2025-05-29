pub mod error;
use self::error::Error;

pub mod response_builder;
pub mod sp_extractor;
pub mod verified_request;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::{asn1::Asn1Time, pkey, x509};
use std::str::FromStr;

use crate::crypto::{self};

use crate::idp::response_builder::{build_response_template, ResponseAttribute};
use crate::metadata::NameIdFormat;
use crate::schema::Response;
use crate::signature::DigestAlgorithm;
use crate::traits::ToXml;

pub struct IdentityProvider {
    private_key: pkey::PKey<Private>,
}

pub enum Rsa {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl Rsa {
    fn bit_length(&self) -> u32 {
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
        let private_key = match key_type {
            KeyType::Rsa(rsa) => {
                let bit_length = rsa.bit_length();
                let rsa = openssl::rsa::Rsa::generate(bit_length)?;
                pkey::PKey::from_rsa(rsa)?
            }
            KeyType::Elliptic(ecc) => {
                let nid = match ecc {
                    Elliptic::NISTP256 => Nid::X9_62_PRIME256V1,
                };
                let group = EcGroup::from_curve_name(nid)?;
                let private_key: EcKey<Private> = EcKey::generate(&group)?;
                pkey::PKey::from_ec_key(private_key)?
            }
        };

        Ok(IdentityProvider { private_key })
    }

    pub fn from_rsa_private_key_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let rsa = openssl::rsa::Rsa::private_key_from_der(der_bytes)?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider { private_key })
    }

    pub fn export_private_key_der(&self) -> Result<Vec<u8>, Error> {
        if let Ok(ec_key) = self.private_key.ec_key() {
            Ok(ec_key.private_key_to_der()?)
        } else if let Ok(rsa) = self.private_key.rsa() {
            Ok(rsa.private_key_to_der()?)
        } else {
            Err(Error::UnexpectedError)?
        }
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
        idp_x509_cert_der: &[u8],
        subject_name_id: &str,
        audience: &str,
        acs_url: &str,
        issuer: &str,
        in_response_to_id: &str,
        attributes: &[ResponseAttribute],
        optional_arguments: &OptionalSigningArgs,
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let response = build_response_template(
            idp_x509_cert_der,
            subject_name_id,
            audience,
            issuer,
            acs_url,
            in_response_to_id,
            attributes,
            &optional_arguments.name_id_format,
            &optional_arguments.not_before,
            &optional_arguments.not_on_or_after,
            &optional_arguments.digest_algorithm,
            &optional_arguments.destination.as_deref(),
            &optional_arguments.recipient.as_deref(),
        );

        let response_xml_unsigned = response.to_string()?;
        let signed_xml = crypto::sign_xml(
            response_xml_unsigned.as_str(),
            self.export_private_key_der()?.as_slice(),
        )?;
        let signed_response = Response::from_str(signed_xml.as_str())?;
        Ok(signed_response)
    }
}

/// A set of optional arguments that are not broken out by the default `samael`
/// crate.
pub struct OptionalSigningArgs {
    /// The `NotBefore` field in the `Conditions`. I.e. the response is not
    /// valid before this time.
    not_before: Option<DateTime<Utc>>,

    /// The `NotOnOrAfter` field in the `Conditions`. I.e. the response is not
    /// valid on or after this time.
    not_on_or_after: Option<DateTime<Utc>>,

    /// The top-level `Destination` tag. Will use the ACS url if not specified.
    destination: Option<String>,

    /// The `Recipient` field in the `SubjectConfirmationData`. Will use the ACS
    /// if not specified.
    recipient: Option<String>,

    /// Indicates the format used by the `NameId` field.
    name_id_format: NameIdFormat,

    /// Defines which algorithm should be used to generate the assertion digest.
    digest_algorithm: DigestAlgorithm,
}

impl Default for OptionalSigningArgs {
    fn default() -> Self {
        Self {
            not_before: None,
            not_on_or_after: None,
            destination: None,
            recipient: None,
            name_id_format: NameIdFormat::default(),
            digest_algorithm: DigestAlgorithm::default(),
        }
    }
}

impl OptionalSigningArgs {
    pub fn with_not_before(self, not_before: DateTime<Utc>) -> Self {
        Self {
            not_before: Some(not_before),
            ..self
        }
    }

    pub fn with_not_on_or_after(self, not_on_or_after: DateTime<Utc>) -> Self {
        Self {
            not_on_or_after: Some(not_on_or_after),
            ..self
        }
    }

    pub fn with_destination(self, destination: String) -> Self {
        Self {
            destination: Some(destination),
            ..self
        }
    }

    pub fn with_recipient(self, recipient: String) -> Self {
        Self {
            recipient: Some(recipient),
            ..self
        }
    }

    pub fn with_name_id_format(self, name_id_format: NameIdFormat) -> Self {
        Self {
            name_id_format,
            ..self
        }
    }

    pub fn with_digest_algorithm(self, digest_algorithm: DigestAlgorithm) -> Self {
        Self {
            digest_algorithm,
            ..self
        }
    }
}
