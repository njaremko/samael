pub mod authn_request;
mod conditions;
mod issuer;
mod name_id_policy;
mod response;
mod subject;

pub use authn_request::AuthnRequest;
pub use conditions::*;
pub use issuer::Issuer;
pub use name_id_policy::NameIdPolicy;
pub use response::Response;
pub use subject::*;

use crate::attribute::Attribute;
use crate::signature::Signature;
use chrono::prelude::*;
use serde::Deserialize;

use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LogoutRequest {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<String>,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "SessionIndex")]
    pub session_index: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Assertion {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Issuer")]
    pub issuer: Issuer,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Subject")]
    pub subject: Option<Subject>,
    #[serde(rename = "Conditions")]
    pub conditions: Option<Conditions>,
    #[serde(rename = "AuthnStatement")]
    pub authn_statements: Option<Vec<AuthnStatement>>,
    #[serde(rename = "AttributeStatement")]
    pub attribute_statements: Option<Vec<AttributeStatement>>,
}

impl Assertion {
    fn name() -> &'static str {
        "saml2:Assertion"
    }

    fn schema() -> &'static [(&'static str, &'static str)] {
        &[
            ("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion"),
            ("xmlns:xsd", "http://www.w3.org/2001/XMLSchema"),
        ]
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        for attr in Self::schema() {
            root.push_attribute((attr.0, attr.1));
        }

        root.push_attribute(("ID", self.id.as_ref()));
        root.push_attribute(("Version", self.version.as_ref()));
        root.push_attribute((
            "IssueInstant",
            self.issue_instant
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_ref(),
        ));

        writer.write_event(Event::Start(root))?;
        writer.write(self.issuer.to_xml()?.as_bytes())?;

        if let Some(subject) = &self.subject {
            writer.write(subject.to_xml()?.as_bytes())?;
        }

        if let Some(conditions) = &self.conditions {
            writer.write(conditions.to_xml()?.as_bytes())?;
        }

        if let Some(signature) = &self.signature {
            writer.write(signature.to_xml()?.as_bytes())?;
        }

        if let Some(statements) = &self.authn_statements {
            for statement in statements {
                writer.write(statement.to_xml()?.as_bytes())?;
            }
        }

        if let Some(statements) = &self.attribute_statements {
            for statement in statements {
                writer.write(statement.to_xml()?.as_bytes())?;
            }
        }

        //TODO: attributeStatement
        writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeStatement {
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute>,
}

impl AttributeStatement {
    fn name() -> &'static str {
        "saml2:AttributeStatement"
    }

    fn schema() -> &'static [(&'static str, &'static str)] {
        &[("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion")]
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        for attr in Self::schema() {
            root.push_attribute((attr.0, attr.1));
        }

        writer.write_event(Event::Start(root))?;

        for attr in &self.attributes {
            writer.write(attr.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnStatement {
    #[serde(rename = "AuthnInstant")]
    pub authn_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "SessionIndex")]
    pub session_index: Option<String>,
    #[serde(rename = "SessionNotOnOrAfter")]
    pub session_not_on_or_after: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "SubjectLocality")]
    pub subject_locality: Option<SubjectLocality>,
    #[serde(rename = "AuthnContext")]
    pub authn_context: Option<AuthnContext>,
}

impl AuthnStatement {
    fn name() -> &'static str {
        "saml2:AuthnStatement"
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        if let Some(session) = &self.session_index {
            root.push_attribute(("SessionIndex", session.as_ref()));
        }

        if let Some(instant) = &self.authn_instant {
            root.push_attribute((
                "AuthnInstant",
                instant
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }

        if let Some(not_after) = &self.session_not_on_or_after {
            root.push_attribute((
                "SessionNotOnOrAfter",
                not_after
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }

        //TODO subject locality

        writer.write_event(Event::Start(root))?;

        if let Some(context) = &self.authn_context {
            writer.write(context.to_xml()?.as_bytes())?;
        }

        writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectLocality {
    #[serde(rename = "Address")]
    pub address: Option<String>,
    #[serde(rename = "DNSName")]
    pub dns_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnContext {
    #[serde(rename = "AuthnContextClassRef")]
    pub value: Option<AuthnContextClassRef>,
}

impl AuthnContext {
    fn name() -> &'static str {
        "saml2:AuthnContext"
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(value) = &self.value {
            let mut write_buf = Vec::new();
            let mut writer = Writer::new(Cursor::new(&mut write_buf));
            let root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

            writer.write_event(Event::Start(root))?;
            writer.write(value.to_xml()?.as_bytes())?;
            writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
            Ok(String::from_utf8(write_buf)?)
        } else {
            Ok(String::new())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnContextClassRef {
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl AuthnContextClassRef {
    fn name() -> &'static str {
        "saml2:AuthnContextClassRef"
    }

    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        if let Some(value) = &self.value {
            let mut write_buf = Vec::new();
            let mut writer = Writer::new(Cursor::new(&mut write_buf));
            let root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

            writer.write_event(Event::Start(root))?;
            writer.write(value.as_bytes())?;
            writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
            Ok(String::from_utf8(write_buf)?)
        } else {
            Ok(String::new())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Status {
    #[serde(rename = "StatusCode")]
    pub status_code: StatusCode,
    #[serde(rename = "StatusMessage")]
    pub status_message: Option<StatusMessage>,
    #[serde(rename = "StatusDetail")]
    pub status_detail: Option<StatusDetail>,
}

impl Status {
    fn name() -> &'static str {
        "saml2p:Status"
    }
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        writer.write_event(Event::Start(root))?;
        writer.write(self.status_code.to_xml()?.as_bytes())?;
        writer.write_event(Event::End(BytesEnd::borrowed(Self::name().as_bytes())))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusCode {
    #[serde(rename = "Value")]
    pub value: Option<String>,
}

impl StatusCode {
    fn name() -> &'static str {
        "saml2p:StatusCode"
    }
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::borrowed(Self::name().as_bytes(), Self::name().len());

        if let Some(value) = &self.value {
            root.push_attribute(("Value", value.as_ref()));
        }

        writer.write_event(Event::Empty(root))?;
        Ok(String::from_utf8(write_buf)?)
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusMessage {
    #[serde(rename = "Value")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusDetail {
    #[serde(rename = "Children")]
    pub children: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LogoutResponse {
    #[serde(rename = "ID")]
    pub id: Option<String>,
    #[serde(rename = "InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<String>,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Consent")]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Status")]
    pub status: Option<Status>,
}
