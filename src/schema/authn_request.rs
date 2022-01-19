use crate::schema::{Conditions, Issuer, Subject};
use crate::signature::Signature;
use crate::utils::UtcDateTime;
use chrono::prelude::*;
use snafu::Snafu;
use std::str::FromStr;
use yaserde_derive::{YaDeserialize, YaSerialize};

#[cfg(feature = "xmlsec")]
use crate::crypto;

use super::NameIdPolicy;

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(
    namespace = "ds: http://www.w3.org/2000/09/xmldsig#",
    namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion",
    namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol"
)]
pub struct AuthnRequest {
    #[yaserde(attribute, rename = "ID")]
    pub id: String,
    #[yaserde(attribute, rename = "Version")]
    pub version: String,
    #[yaserde(attribute, rename = "IssueInstant", TODO)]
    pub issue_instant: UtcDateTime,
    #[yaserde(attribute, rename = "Destination")]
    pub destination: Option<String>,
    #[yaserde(attribute, rename = "Consent")]
    pub consent: Option<String>,
    #[yaserde(attribute, rename = "ForceAuthn")]
    pub force_authn: Option<bool>,
    #[yaserde(attribute, rename = "IsPassive")]
    pub is_passive: Option<bool>,
    #[yaserde(attribute, rename = "ProtocolBinding")]
    pub protocol_binding: Option<String>,
    #[yaserde(attribute, rename = "AssertionConsumerServiceIndex")]
    pub assertion_consumer_service_index: Option<u16>,
    #[yaserde(attribute, rename = "AssertionConsumerServiceURL")]
    pub assertion_consumer_service_url: Option<String>,
    #[yaserde(attribute, rename = "AttributeConsumingServiceIndex")]
    pub attribute_consuming_service_index: Option<u16>,
    #[yaserde(attribute, rename = "ProviderName")]
    pub provider_name: Option<String>,
    #[yaserde(rename = "Issuer", prefix = "saml")]
    pub issuer: Option<Issuer>,
    #[yaserde(rename = "Signature", prefix = "ds")]
    pub signature: Option<Signature>,
    #[yaserde(rename = "Subject", prefix = "saml")]
    pub subject: Option<Subject>,
    #[yaserde(rename = "NameIDPolicy", prefix = "samlp")]
    pub name_id_policy: Option<NameIdPolicy>,
    #[yaserde(rename = "Conditions", prefix = "saml")]
    pub conditions: Option<Conditions>,
    #[yaserde(rename = "RequestedAuthnContext", prefix = "samlp")]
    pub requested_authn_context: Option<RequestedAuthnContext>,
    #[yaserde(rename = "Scoping", prefix = "samlp")]
    pub scoping: Option<Scoping>,
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize AuthnRequest: {:?}", message))]
    ParseError {
        message: String,
    },

    NoSubjectNameID,
}

impl FromStr for AuthnRequest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        yaserde::de::from_str(s).map_err(|message| Error::ParseError { message })
    }
}

impl AuthnRequest {
    pub fn subject_name_id(&self) -> Result<String, Error> {
        Ok(self
            .subject
            .clone()
            .and_then(|s| s.name_id)
            .ok_or(Error::NoSubjectNameID)?
            .value)
    }

    pub fn issuer_at(&self) -> &DateTime<Utc> {
        &self.issue_instant.0
    }

    pub fn issuer_value(&self) -> Option<String> {
        self.issuer.clone().and_then(|iss| iss.value)
    }

    pub fn add_key_info(&mut self, public_cert_der: &[u8]) -> &mut Self {
        if let Some(ref mut signature) = self.signature {
            signature.add_key_info(public_cert_der);
        }
        self
    }

    pub fn as_xml(&self) -> Result<String, String> {
        yaserde::ser::to_string(self)
    }

    #[cfg(feature = "xmlsec")]
    pub fn to_signed_xml(
        &self,
        private_key_der: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        crypto::sign_xml(self.as_xml()?, private_key_der)
            .map_err(|crypto_error| Box::new(crypto_error) as Box<dyn std::error::Error>)
    }
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "saml: urn:oasis:names:tc:SAML:2.0:assertion")]
pub struct RequestedAuthnContext {
    #[yaserde(rename = "AuthnContextClassRef", prefix = "saml", default)]
    authn_context_class_ref: Vec<String>,
    #[yaserde(rename = "AuthnContextDeclRef", prefix = "saml", default)]
    authn_context_decl_ref: Vec<String>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol")]
pub struct Scoping {
    #[yaserde(attribute, rename = "ProxyCount")]
    proxy_count: Option<u32>,
    #[yaserde(rename = "IDPList", prefix = "samlp")]
    idp_list: Option<IdpList>,
    #[yaserde(rename = "RequesterID", prefix = "samlp", default)]
    requester_id: Option<String>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
#[yaserde(namespace = "samlp: urn:oasis:names:tc:SAML:2.0:protocol")]
pub struct IdpList {
    #[yaserde(rename = "IDPEntry", prefix = "samlp")]
    idp_entries: Vec<IdpEntry>,
    #[yaserde(rename = "GetComplete", prefix = "samlp")]
    get_complete: Option<String>,
}

#[derive(
    Clone, Debug, Default, YaDeserialize, Hash, Eq, PartialEq, Ord, PartialOrd, YaSerialize,
)]
pub struct IdpEntry {
    #[yaserde(attribute, rename = "ProviderID")]
    provider_id: String,
    #[yaserde(attribute, rename = "Name")]
    name: Option<String>,
    #[yaserde(attribte, rename = "Loc")]
    loc: Option<String>,
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(feature = "xmlsec")]
    pub fn test_signed_authn() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/private.der"
        ));

        let public_cert = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/public.der"
        ));

        let authn_request_sign_template = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/authn_request_sign_template.xml"
        ));

        let signed_authn_request = authn_request_sign_template
            .parse::<super::AuthnRequest>()?
            .add_key_info(public_cert)
            .to_signed_xml(private_key)?;

        assert!(crate::crypto::verify_signed_xml(
            &signed_authn_request,
            &public_cert[..],
            Some("ID"),
        )
        .is_ok());

        Ok(())
    }
}
