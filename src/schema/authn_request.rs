use crate::schema::{Conditions, Issuer, NameIdPolicy, Subject};
use crate::signature::Signature;
use chrono::prelude::*;
use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "samlp:AuthnRequest";

#[derive(Clone, Debug, Deserialize)]
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

impl AuthnRequest {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(NAME.as_bytes(), NAME.len());
        root.push_attribute(("ID", self.id.as_ref()));
        root.push_attribute(("Version", self.version.as_ref()));
        root.push_attribute((
            "IssueInstant",
            self.issue_instant
                .to_rfc3339_opts(SecondsFormat::Secs, true)
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
}
