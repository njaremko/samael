use crate::schema::{Conditions, Issuer, NameIdPolicy, Subject};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use snafu::Snafu;
use std::io::Cursor;
use std::str::FromStr;

#[cfg(feature = "xmlsec")]
use crate::crypto;

const NAME: &str = "saml2p:AuthnRequest";
const SCHEMA: (&str, &str) = ("xmlns:saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnRequest {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Consent")]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Subject")]
    pub subject: Option<Subject>,
    #[serde(rename = "NameIDPolicy")]
    pub name_id_policy: Option<NameIdPolicy>,
    #[serde(rename = "Conditions")]
    pub conditions: Option<Conditions>,
    #[serde(rename = "ForceAuthn")]
    pub force_authn: Option<bool>,
    #[serde(rename = "IsPassive")]
    pub is_passive: Option<bool>,
    #[serde(rename = "AssertionConsumerServiceIndex")]
    pub assertion_consumer_service_index: Option<usize>,
    #[serde(rename = "AssertionConsumerServiceURL")]
    pub assertion_consumer_service_url: Option<String>,
    #[serde(rename = "ProtocolBinding")]
    pub protocol_binding: Option<String>,
    #[serde(rename = "AttributeConsumingServiceIndex")]
    pub attribute_consuming_service_index: Option<usize>,
    #[serde(rename = "ProviderName")]
    pub provider_name: Option<String>,
}

impl Default for AuthnRequest {
    fn default() -> Self {
        AuthnRequest {
            id: "".to_string(),
            version: "".to_string(),
            issue_instant: Utc::now(),
            destination: None,
            consent: None,
            issuer: None,
            signature: None,
            subject: None,
            name_id_policy: None,
            conditions: None,
            force_authn: None,
            is_passive: None,
            assertion_consumer_service_index: None,
            assertion_consumer_service_url: None,
            protocol_binding: None,
            attribute_consuming_service_index: None,
            provider_name: None,
        }
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to deserialize AuthnRequest: {:?}", source))]
    #[snafu(context(false))]
    ParseError {
        source: quick_xml::DeError,
    },

    NoSubjectNameID,
}

impl FromStr for AuthnRequest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
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
        &self.issue_instant
    }

    pub fn issuer_value(&self) -> Option<String> {
        self.issuer.clone().and_then(|iss| iss.value)
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new(
            "1.0".as_bytes(),
            Some("UTF-8".as_bytes()),
            None,
        )))?;

        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(SCHEMA);
        root.push_attribute(("ID", self.id.as_ref()));
        root.push_attribute(("Version", self.version.as_ref()));
        root.push_attribute((
            "IssueInstant",
            self.issue_instant
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_ref(),
        ));

        if let Some(destination) = &self.destination {
            root.push_attribute(("Destination", destination.as_ref()));
        }
        if let Some(consent) = &self.consent {
            root.push_attribute(("Consent", consent.as_ref()));
        }
        if let Some(force_authn) = &self.force_authn {
            root.push_attribute(("ForceAuthn", force_authn.to_string().as_ref()));
        }
        if let Some(is_passive) = &self.is_passive {
            root.push_attribute(("IsPassive", is_passive.to_string().as_ref()));
        }
        if let Some(protocol_binding) = &self.protocol_binding {
            root.push_attribute(("ProtocolBinding", protocol_binding.as_ref()));
        }
        if let Some(assertion_consumer_service_index) = &self.assertion_consumer_service_index {
            root.push_attribute((
                "AssertionConsumerServiceIndex",
                assertion_consumer_service_index.to_string().as_ref(),
            ));
        }
        if let Some(assertion_consumer_service_url) = &self.assertion_consumer_service_url {
            root.push_attribute((
                "AssertionConsumerServiceURL",
                assertion_consumer_service_url.as_ref(),
            ));
        }
        if let Some(attribute_consuming_service_index) = &self.attribute_consuming_service_index {
            root.push_attribute((
                "AttributeConsumingServiceIndex	",
                attribute_consuming_service_index.to_string().as_ref(),
            ));
        }
        if let Some(provider_name) = &self.provider_name {
            root.push_attribute(("ProviderName", provider_name.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(issuer) = &self.issuer {
            writer.write(issuer.to_xml()?.as_bytes())?;
        }
        if let Some(signature) = &self.signature {
            writer.write(signature.to_xml()?.as_bytes())?;
        }
        if let Some(subject) = &self.subject {
            writer.write(subject.to_xml()?.as_bytes())?;
        }
        if let Some(name_id_policy) = &self.name_id_policy {
            writer.write(name_id_policy.to_xml()?.as_bytes())?;
        }
        if let Some(conditions) = &self.conditions {
            writer.write(conditions.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(NAME.as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }

    pub fn add_key_info(&mut self, public_cert_der: &[u8]) -> &mut Self {
        if let Some(ref mut signature) = self.signature {
            signature.add_key_info(public_cert_der);
        }
        self
    }

    #[cfg(feature = "xmlsec")]
    pub fn to_signed_xml(
        &self,
        private_key_der: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        crypto::sign_xml(self.to_xml()?, private_key_der)
            .map_err(|crypto_error| Box::new(crypto_error) as Box<dyn std::error::Error>)
    }
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
