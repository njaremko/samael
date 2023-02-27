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

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LogoutRequest {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@Destination")]
    pub destination: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "@SessionIndex")]
    pub session_index: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Assertion {
    #[serde(rename = "@ID")]
    pub id: String,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "@Version")]
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
}

impl TryFrom<Assertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Assertion) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Assertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Assertion) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(Assertion::name());

        for attr in Assertion::schema() {
            root.push_attribute((attr.0, attr.1));
        }

        root.push_attribute(("ID", value.id.as_ref()));
        root.push_attribute(("Version", value.version.as_ref()));
        root.push_attribute((
            "IssueInstant",
            value
                .issue_instant
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_ref(),
        ));

        writer.write_event(Event::Start(root))?;
        let event: Event<'_> = (&value.issuer).try_into()?;
        writer.write_event(event)?;

        if let Some(signature) = &value.signature {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(subject) = &value.subject {
            let event: Event<'_> = subject.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(conditions) = &value.conditions {
            let event: Event<'_> = conditions.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(statements) = &value.authn_statements {
            for statement in statements {
                let event: Event<'_> = statement.try_into()?;
                writer.write_event(event)?;
            }
        }

        if let Some(statements) = &value.attribute_statements {
            for statement in statements {
                let event: Event<'_> = statement.try_into()?;
                writer.write_event(event)?;
            }
        }

        //TODO: attributeStatement
        writer.write_event(Event::End(BytesEnd::new(Assertion::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
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
}

impl TryFrom<AttributeStatement> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AttributeStatement) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AttributeStatement> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AttributeStatement) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(AttributeStatement::name());

        for attr in AttributeStatement::schema() {
            root.push_attribute((attr.0, attr.1));
        }

        writer.write_event(Event::Start(root))?;

        for attr in &value.attributes {
            let event: Event<'_> = attr.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(AttributeStatement::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnStatement {
    #[serde(rename = "@AuthnInstant")]
    pub authn_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@SessionIndex")]
    pub session_index: Option<String>,
    #[serde(rename = "@SessionNotOnOrAfter")]
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
}

impl TryFrom<AuthnStatement> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AuthnStatement) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AuthnStatement> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthnStatement) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(AuthnStatement::name());

        if let Some(session) = &value.session_index {
            root.push_attribute(("SessionIndex", session.as_ref()));
        }

        if let Some(instant) = &value.authn_instant {
            root.push_attribute((
                "AuthnInstant",
                instant
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }

        if let Some(not_after) = &value.session_not_on_or_after {
            root.push_attribute((
                "SessionNotOnOrAfter",
                not_after
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }

        //TODO subject locality

        writer.write_event(Event::Start(root))?;

        if let Some(context) = &value.authn_context {
            let event: Event<'_> = context.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(AuthnStatement::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubjectLocality {
    #[serde(rename = "@Address")]
    pub address: Option<String>,
    #[serde(rename = "@DNSName")]
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
}

impl TryFrom<AuthnContext> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AuthnContext) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AuthnContext> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthnContext) -> Result<Self, Self::Error> {
        if let Some(value) = &value.value {
            let mut write_buf = Vec::new();
            let mut writer = Writer::new(Cursor::new(&mut write_buf));
            let root = BytesStart::new(AuthnContext::name());

            writer.write_event(Event::Start(root))?;
            let event: Event<'_> = value.try_into()?;
            writer.write_event(event)?;
            writer.write_event(Event::End(BytesEnd::new(AuthnContext::name())))?;
            Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
                write_buf,
            )?)))
        } else {
            Ok(Event::Text(BytesText::from_escaped(String::new())))
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
}

impl TryFrom<AuthnContextClassRef> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AuthnContextClassRef) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AuthnContextClassRef> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthnContextClassRef) -> Result<Self, Self::Error> {
        if let Some(value) = &value.value {
            let mut write_buf = Vec::new();
            let mut writer = Writer::new(Cursor::new(&mut write_buf));
            let root = BytesStart::new(AuthnContextClassRef::name());

            writer.write_event(Event::Start(root))?;
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
            writer.write_event(Event::End(BytesEnd::new(AuthnContextClassRef::name())))?;
            Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
                write_buf,
            )?)))
        } else {
            Ok(Event::Text(BytesText::from_escaped(String::new())))
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
}

impl TryFrom<Status> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Status) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Status> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Status) -> Result<Self, Self::Error> {
        let mut write_buf: Vec<u8> = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(Status::name());

        writer.write_event(Event::Start(root))?;
        let event: Event<'_> = (&value.status_code).try_into()?;
        writer.write_event(event)?;
        writer.write_event(Event::End(BytesEnd::new(Status::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusCode {
    #[serde(rename = "@Value")]
    pub value: Option<String>,
}

impl StatusCode {
    fn name() -> &'static str {
        "saml2p:StatusCode"
    }
}

impl TryFrom<StatusCode> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: StatusCode) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&StatusCode> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &StatusCode) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(StatusCode::name());

        if let Some(value) = &value.value {
            root.push_attribute(("Value", value.as_ref()));
        }

        writer.write_event(Event::Empty(root))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusMessage {
    #[serde(rename = "@Value")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct StatusDetail {
    #[serde(rename = "@Children")]
    pub children: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LogoutResponse {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@Destination")]
    pub destination: Option<String>,
    #[serde(rename = "@Consent")]
    pub consent: Option<String>,
    #[serde(rename = "Issuer")]
    pub issuer: Option<Issuer>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Status")]
    pub status: Option<Status>,
}
