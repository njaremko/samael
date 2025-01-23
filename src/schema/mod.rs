pub mod authn_request;
mod conditions;
mod issuer;
mod name_id_policy;
mod requested_authn_context;
mod response;
mod subject;

pub use authn_request::AuthnRequest;
pub use conditions::*;
pub use issuer::Issuer;
pub use name_id_policy::NameIdPolicy;
pub use requested_authn_context::{AuthnContextComparison, RequestedAuthnContext};
pub use response::Response;
pub use subject::*;

use crate::attribute::Attribute;
use crate::signature::Signature;
use chrono::prelude::*;
use serde::Deserialize;

use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;

use std::io::Cursor;
use std::str::FromStr;

use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct NameID {
    #[serde(rename = "Format")]
    pub format: Option<String>,

    #[serde(rename = "$value")]
    pub value: String,
}

impl NameID {
    fn name() -> &'static str {
        "saml2:NameID"
    }

    fn schema() -> &'static [(&'static str, &'static str)] {
        &[("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion")]
    }
}

impl TryFrom<&NameID> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &NameID) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NameID::name());

        for attr in NameID::schema() {
            root.push_attribute((attr.0, attr.1));
        }

        if let Some(format) = &value.format {
            root.push_attribute(("Format", format.as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(NameID::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

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
    #[serde(rename = "NameID")]
    pub name_id: Option<NameID>,
}

#[derive(Debug, Error)]
pub enum LogoutRequestError {
    #[error("Failed to deserialize LogoutRequest: {:?}", source)]
    ParseError {
        #[from]
        source: quick_xml::DeError,
    },
}

impl FromStr for LogoutRequest {
    type Err = LogoutRequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

const LOGOUT_REQUEST_NAME: &str = "saml2p:LogoutRequest";
const SESSION_INDEX_NAME: &str = "saml2p:SessionIndex";
const PROTOCOL_SCHEMA: (&str, &str) = ("xmlns:saml2p", "urn:oasis:names:tc:SAML:2.0:protocol");

impl TryFrom<LogoutRequest> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: LogoutRequest) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&LogoutRequest> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &LogoutRequest) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let mut root = BytesStart::new(LOGOUT_REQUEST_NAME);
        root.push_attribute(PROTOCOL_SCHEMA);
        if let Some(id) = &value.id {
            root.push_attribute(("ID", id.as_ref()));
        }
        if let Some(version) = &value.version {
            root.push_attribute(("Version", version.as_ref()));
        }
        if let Some(issue_instant) = &value.issue_instant {
            root.push_attribute((
                "IssueInstant",
                issue_instant
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(destination) = &value.destination {
            root.push_attribute(("Destination", destination.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(issuer) = &value.issuer {
            let event: Event<'_> = issuer.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(signature) = &value.signature {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(session) = &value.session_index {
            writer.write_event(Event::Start(BytesStart::new(SESSION_INDEX_NAME)))?;
            writer.write_event(Event::Text(BytesText::new(session)))?;
            writer.write_event(Event::End(BytesEnd::new(SESSION_INDEX_NAME)))?;
        }
        if let Some(name_id) = &value.name_id {
            let event: Event<'_> = name_id.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(LOGOUT_REQUEST_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
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

impl FromStr for Assertion {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
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
pub struct AuthnContextDeclRef {
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl AuthnContextDeclRef {
    fn name() -> &'static str {
        "saml2:AuthnContextDeclRef"
    }
}

impl TryFrom<AuthnContextDeclRef> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AuthnContextDeclRef) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AuthnContextDeclRef> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthnContextDeclRef) -> Result<Self, Self::Error> {
        if let Some(value) = &value.value {
            let mut write_buf = Vec::new();
            let mut writer = Writer::new(Cursor::new(&mut write_buf));
            let root = BytesStart::new(AuthnContextDeclRef::name());

            writer.write_event(Event::Start(root))?;
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
            writer.write_event(Event::End(BytesEnd::new(AuthnContextDeclRef::name())))?;
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
        if let Some(status_message) = value.status_message.as_ref() {
            let event: Event<'_> = status_message.try_into()?;
            writer.write_event(event)?;
        }
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
pub struct StatusMessage(pub Option<String>);

impl StatusMessage {
    fn name() -> &'static str {
        "saml2p:StatusMessage"
    }
}

impl TryFrom<&StatusMessage> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &StatusMessage) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));

        writer.write_event(Event::Start(BytesStart::new(StatusMessage::name())))?;
        if let Some(content) = &value.0 {
            writer.write_event(Event::Text(BytesText::from_escaped(content)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(StatusMessage::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
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

#[derive(Debug, Error)]
pub enum LogoutResponseError {
    #[error("Failed to deserialize LogoutResponse: {:?}", source)]
    ParseError {
        #[from]
        source: quick_xml::DeError,
    },
}

impl FromStr for LogoutResponse {
    type Err = LogoutResponseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

const LOGOUT_RESPONSE_NAME: &str = "saml2p:LogoutResponse";

impl TryFrom<LogoutResponse> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: LogoutResponse) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&LogoutResponse> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &LogoutResponse) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let mut root = BytesStart::new(LOGOUT_RESPONSE_NAME);
        root.push_attribute(PROTOCOL_SCHEMA);
        if let Some(id) = &value.id {
            root.push_attribute(("ID", id.as_ref()));
        }
        if let Some(resp_to) = &value.in_response_to {
            root.push_attribute(("InResponseTo", resp_to.as_ref()));
        }
        if let Some(version) = &value.version {
            root.push_attribute(("Version", version.as_ref()));
        }
        if let Some(issue_instant) = &value.issue_instant {
            root.push_attribute((
                "IssueInstant",
                issue_instant
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(destination) = &value.destination {
            root.push_attribute(("Destination", destination.as_ref()));
        }
        if let Some(consent) = &value.consent {
            root.push_attribute(("Consent", consent.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        if let Some(issuer) = &value.issuer {
            let event: Event<'_> = issuer.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(signature) = &value.signature {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(status) = &value.status {
            let event: Event<'_> = status.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(LOGOUT_RESPONSE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod test {
    use super::{LogoutRequest, LogoutResponse};
    use crate::traits::ToXml;

    #[test]
    fn test_deserialize_serialize_logout_request() {
        let request_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/logout_request.xml",
        ));
        let expected_request: LogoutRequest = request_xml
            .parse()
            .expect("failed to parse logout_request.xml");
        let serialized_request = expected_request
            .to_string()
            .expect("failed to convert request to xml");
        let actual_request: LogoutRequest = serialized_request
            .parse()
            .expect("failed to re-parse request");

        assert_eq!(expected_request, actual_request);
    }

    #[test]
    fn test_deserialize_serialize_logout_response() {
        let response_xml = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_vectors/logout_response.xml",
        ));
        let expected_response: LogoutResponse = response_xml
            .parse()
            .expect("failed to parse logout_response.xml");
        let serialized_response = expected_response
            .to_string()
            .expect("failed to convert Response to xml");
        let actual_response: LogoutResponse = serialized_response
            .parse()
            .expect("failed to re-parse Response");

        assert_eq!(expected_response, actual_response);
    }
}
